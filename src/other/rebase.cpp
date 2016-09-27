/* -*- mode: C++; c-basic-offset: 4; tab-width: 4 -*- 
 *
 * Copyright (c) 2006-2012 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <vector>
#include <set>
#include <unordered_map>


#include "MachOFileAbstraction.hpp"
#include "Architectures.hpp"

static bool verbose = false;

__attribute__((noreturn))
void throwf(const char* format, ...) 
{
	va_list	list;
	char*	p;
	va_start(list, format);
	vasprintf(&p, format, list);
	va_end(list);
	
	const char*	t = p;
	throw t;
}


class AbstractRebaser
{
public:
	virtual cpu_type_t							getArchitecture() const = 0;
	virtual void								rebase() = 0;
};


template <typename A>
class Rebaser : public AbstractRebaser
{
public:
												Rebaser(const void* machHeader);
	virtual										~Rebaser() {}

	virtual cpu_type_t							getArchitecture() const;
	virtual void								rebase();

private:
	typedef typename A::P					P;
	typedef typename A::P::E				E;
	typedef typename A::P::uint_t			pint_t;
	
	struct vmmap { pint_t vmaddr; pint_t vmsize; pint_t fileoff; };
	
	void										adjustDATA();
	void										rebaseAt(int segIndex, uint64_t offset, uint8_t type);
	
	const macho_header<P>*						fHeader;
	std::unordered_map<const char *, uint32_t>	counts;
};



class MultiArchRebaser
{
public:
												MultiArchRebaser(const char* path, bool writable=false);
												~MultiArchRebaser();

	const std::vector<AbstractRebaser*>&		getArchs() const { return fRebasers; }

private:
	std::vector<AbstractRebaser*>				fRebasers;
	void*										fMappingAddress;
	uint64_t									fFileSize;
};



MultiArchRebaser::MultiArchRebaser(const char* path, bool writable)
 : fMappingAddress(0), fFileSize(0)
{
	// map in whole file
	int fd = ::open(path, (writable ? O_RDWR : O_RDONLY), 0);
	if ( fd == -1 )
		throwf("can't open file %s, errno=%d", path, errno);
	struct stat stat_buf;
	if ( fstat(fd, &stat_buf) == -1)
		throwf("can't stat open file %s, errno=%d", path, errno);
	if ( stat_buf.st_size < 20 )
		throwf("file too small %s", path);
	const int prot = writable ? (PROT_READ | PROT_WRITE) : PROT_READ;
	const int flags = writable ? (MAP_FILE | MAP_SHARED) : (MAP_FILE | MAP_PRIVATE);
	uint8_t* p = (uint8_t*)::mmap(NULL, stat_buf.st_size, prot, flags, fd, 0);
	if ( p == (uint8_t*)(-1) )
		throwf("can't map file %s, errno=%d", path, errno);
	::close(fd);

	// if fat file, process each architecture
	const fat_header* fh = (fat_header*)p;
	const mach_header* mh = (mach_header*)p;
	if ( fh->magic == OSSwapBigToHostInt32(FAT_MAGIC) ) {
		// Fat header is always big-endian
		const struct fat_arch* archs = (struct fat_arch*)(p + sizeof(struct fat_header));
		for (unsigned long i=0; i < OSSwapBigToHostInt32(fh->nfat_arch); ++i) {
			uint32_t fileOffset = OSSwapBigToHostInt32(archs[i].offset);
			try {
				switch ( OSSwapBigToHostInt32(archs[i].cputype) ) {
					case CPU_TYPE_POWERPC:
						fRebasers.push_back(new Rebaser<ppc>(&p[fileOffset]));
						break;
					case CPU_TYPE_POWERPC64:
						fRebasers.push_back(new Rebaser<ppc64>(&p[fileOffset]));
						break;
					case CPU_TYPE_I386:
						fRebasers.push_back(new Rebaser<x86>(&p[fileOffset]));
						break;
					case CPU_TYPE_X86_64:
						fRebasers.push_back(new Rebaser<x86_64>(&p[fileOffset]));
						break;
					case CPU_TYPE_ARM:
						fRebasers.push_back(new Rebaser<arm>(&p[fileOffset]));
						break;
					default:
						throw "unknown file format";
				}
			}
			catch (const char* msg) {
				fprintf(stderr, "rebase warning: %s for %s\n", msg, path);
			}
		}
	}
	else {
		try {
			if ( (OSSwapBigToHostInt32(mh->magic) == MH_MAGIC) && (OSSwapBigToHostInt32(mh->cputype) == CPU_TYPE_POWERPC)) {
				fRebasers.push_back(new Rebaser<ppc>(mh));
			}
			else if ( (OSSwapBigToHostInt32(mh->magic) == MH_MAGIC_64) && (OSSwapBigToHostInt32(mh->cputype) == CPU_TYPE_POWERPC64)) {
				fRebasers.push_back(new Rebaser<ppc64>(mh));
			}
			else if ( (OSSwapLittleToHostInt32(mh->magic) == MH_MAGIC) && (OSSwapLittleToHostInt32(mh->cputype) == CPU_TYPE_I386)) {
				fRebasers.push_back(new Rebaser<x86>(mh));
			}
			else if ( (OSSwapLittleToHostInt32(mh->magic) == MH_MAGIC_64) && (OSSwapLittleToHostInt32(mh->cputype) == CPU_TYPE_X86_64)) {
				fRebasers.push_back(new Rebaser<x86_64>(mh));
			}
			else if ( (OSSwapLittleToHostInt32(mh->magic) == MH_MAGIC) && (OSSwapLittleToHostInt32(mh->cputype) == CPU_TYPE_ARM)) {
				fRebasers.push_back(new Rebaser<arm>(mh));
			}
			else {
				throw "unknown file format";
			}
		}
		catch (const char* msg) {
			fprintf(stderr, "rebase warning: %s for %s\n", msg, path);
		}
	}
	
	fMappingAddress = p;
	fFileSize = stat_buf.st_size;
}


MultiArchRebaser::~MultiArchRebaser()
{
	::munmap(fMappingAddress, fFileSize);
}

template <typename A>
Rebaser<A>::Rebaser(const void* machHeader)
 : 	fHeader((const macho_header<P>*)machHeader)
{
	switch ( fHeader->filetype() ) {
		case MH_EXECUTE:
			break;
		default:
			throw "file is not a dylib or bundle";
	}
		
}

template <> cpu_type_t Rebaser<ppc>::getArchitecture()    const { return CPU_TYPE_POWERPC; }
template <> cpu_type_t Rebaser<ppc64>::getArchitecture()  const { return CPU_TYPE_POWERPC64; }
template <> cpu_type_t Rebaser<x86>::getArchitecture()    const { return CPU_TYPE_I386; }
template <> cpu_type_t Rebaser<x86_64>::getArchitecture() const { return CPU_TYPE_X86_64; }
template <> cpu_type_t Rebaser<arm>::getArchitecture() const { return CPU_TYPE_ARM; }

template <typename A>
void Rebaser<A>::rebase()
{
	// update writable segments that have internal pointers
	this->adjustDATA();
}

static uint64_t read_uleb128(const uint8_t*& p, const uint8_t* end)
{
	uint64_t result = 0;
	int		 bit = 0;
	do {
		if (p == end)
			throwf("malformed uleb128");

		uint64_t slice = *p & 0x7f;

		if (bit >= 64 || slice << bit >> bit != slice)
			throwf("uleb128 too big");
		else {
			result |= (slice << bit);
			bit += 7;
		}
	} 
	while (*p++ & 0x80);
	return result;
}

template <typename A>
void Rebaser<A>::rebaseAt(int segIndex, uint64_t offset, uint8_t type)
{
	//fprintf(stderr, "rebaseAt(seg=%d, offset=0x%08llX, type=%d\n", segIndex, offset, type);
	static int lastSegIndex = -1;
	static uint8_t* lastSegMappedStart = nullptr;
	static macho_segment_command<P>* lastSeg = nullptr;
	
	if ( segIndex != lastSegIndex ) {
		const macho_load_command<P>* const cmds = (macho_load_command<P>*)((uint8_t*)fHeader + sizeof(macho_header<P>));
		const uint32_t cmd_count = fHeader->ncmds();
		const macho_load_command<P>* cmd = cmds;
		int segCount = 0;
		for (uint32_t i = 0; i < cmd_count; ++i) {
			if ( cmd->cmd() == macho_segment_command<P>::CMD ) {
				if ( segIndex == segCount ) {
					lastSeg = (macho_segment_command<P>*)cmd;
					fprintf(stderr, "%s\n", lastSeg->segname());
					lastSegMappedStart = (uint8_t*)fHeader + lastSeg->fileoff();
					lastSegIndex = segCount;
					break;
				}
				++segCount;
			}

			cmd = (const macho_load_command<P>*)(((uint8_t*)cmd)+cmd->cmdsize());
		}	
	}
	
	pint_t* locationToFix = (pint_t*)(lastSegMappedStart+offset);
	uint32_t* locationToFix32 = (uint32_t*)(lastSegMappedStart+offset);
	
	static macho_section<P> * lastSection = nullptr;
	
	offset += lastSeg->fileoff();
	
	if ( lastSection == nullptr || offset < lastSection->reloff() || offset >= lastSection->reloff() + lastSection->size() ) {
		auto sectionsStart = (macho_section<P>*)((char*)lastSeg + sizeof(macho_segment_command<P>));
		
		for (uint32_t i = 0; i < lastSeg->nsects(); ++i) {
			macho_section<P> & sect = sectionsStart[i];
			if (offset >= sect.offset() && offset < sect.offset() + sect.size()) {
				if (verbose) {
					fprintf(stderr, "%s\n", sect.sectname());
				}
				lastSection = &sect;
			}
		}
	}
	
	counts[lastSection->sectname()] += 1;
	
	switch (type) {
		case REBASE_TYPE_POINTER:
			if (verbose) {
				fprintf(stderr, "Would rebase %p\n", locationToFix);
			}
			P::setP(*locationToFix, A::P::getP(*locationToFix));
			break;
		case REBASE_TYPE_TEXT_ABSOLUTE32:
			if (verbose) {
				fprintf(stderr, "Would rebase 32 %p\n", locationToFix32);
			}
			E::set32(*locationToFix32, E::get32(*locationToFix32));
			break;
		default:
			throwf("bad rebase type %d", type);
	}
}


template <typename A>
void Rebaser<A>::adjustDATA()
{
	const macho_dyld_info_command<P>* dyldInfo = nullptr;

	const macho_load_command<P>* const cmds = (macho_load_command<P>*)((uint8_t*)fHeader + sizeof(macho_header<P>));
	const uint32_t cmd_count = fHeader->ncmds();
	const macho_load_command<P>* cmd = cmds;
	for (uint32_t i = 0; i < cmd_count; ++i) {
		switch (cmd->cmd()) {
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				dyldInfo = (macho_dyld_info_command<P>*)cmd;
				break;
		}
		cmd = (const macho_load_command<P>*)(((uint8_t*)cmd)+cmd->cmdsize());
	}	

	// use new encoding of rebase info
	if ( dyldInfo->rebase_size() != 0 ) {
		const uint8_t* p = (uint8_t*)fHeader + dyldInfo->rebase_off();
		const uint8_t* end = &p[dyldInfo->rebase_size()];
		
		uint8_t type = 0;
		uint64_t offset = 0;
		uint32_t count;
		uint32_t skip;
		int segIndex;
		bool done = false;
		while ( !done && (p < end) ) {
			uint8_t immediate = *p & REBASE_IMMEDIATE_MASK;
			uint8_t opcode = *p & REBASE_OPCODE_MASK;
			++p;
			switch (opcode) {
				case REBASE_OPCODE_DONE:
					done = true;
					break;
				case REBASE_OPCODE_SET_TYPE_IMM:
					type = immediate;
					break;
				case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
					segIndex = immediate;
					offset = read_uleb128(p, end);
					break;
				case REBASE_OPCODE_ADD_ADDR_ULEB:
					offset += read_uleb128(p, end);
					break;
				case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
					offset += immediate*sizeof(pint_t);
					break;
				case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
					for (int i=0; i < immediate; ++i) {
						rebaseAt(segIndex, offset, type);
						offset += sizeof(pint_t);
					}
					break;
				case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
					count = read_uleb128(p, end);
					for (uint32_t i=0; i < count; ++i) {
						rebaseAt(segIndex, offset, type);
						offset += sizeof(pint_t);
					}
					break;
				case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
					rebaseAt(segIndex, offset, type);
					offset += read_uleb128(p, end) + sizeof(pint_t);
					break;
				case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
					count = read_uleb128(p, end);
					skip = read_uleb128(p, end);
					for (uint32_t i=0; i < count; ++i) {
						rebaseAt(segIndex, offset, type);
						offset += skip + sizeof(pint_t);
					}
					break;
				default:
					throwf("bad rebase opcode %d", *p);
			}
		}
	}
	
	for (const auto &pair : counts) {
		fprintf(stderr, "%s,%d\n", pair.first, pair.second);
	}

}

// scan dylibs and collect size info
// calculate new base address for each dylib
// rebase each file
//		copy to temp and mmap
//		update content
//		unmap/flush
//		rename

struct archInfo {
	cpu_type_t	arch;
};

struct fileInfo
{
	fileInfo(const char* p) : path(p) {}
	
	const char*				path;
	std::vector<archInfo>	archs;
};

//
// add archInfos to fileInfo for every slice of a fat file
// for ppc, there may be duplicate architectures (with different sub-types)
//
static void setSizes(fileInfo& info, const std::set<cpu_type_t>& onlyArchs)
{
	const MultiArchRebaser mar(info.path);
	const std::vector<AbstractRebaser*>&	rebasers = mar.getArchs();
	for(std::set<cpu_type_t>::iterator ait=onlyArchs.begin(); ait != onlyArchs.end(); ++ait) {
		for(std::vector<AbstractRebaser*>::const_iterator rit=rebasers.begin(); rit != rebasers.end(); ++rit) {
			AbstractRebaser* rebaser = *rit;
			if ( rebaser->getArchitecture() == *ait ) {
				archInfo ai;
				ai.arch = *ait;
				//fprintf(stderr, "base=0x%llX, size=0x%llX\n", ai.orgBase, ai.vmSize);
				info.archs.push_back(ai);
			}
		}
	}
}

static const char* nameForArch(cpu_type_t arch)
{
	switch( arch ) {
		case CPU_TYPE_POWERPC:
			return "ppc";
		case CPU_TYPE_POWERPC64:
			return "ppca64";
		case CPU_TYPE_I386:
			return "i386";
		case CPU_TYPE_X86_64:
			return "x86_64";
		case CPU_TYPE_ARM:
			return "arm";
	}
	return "unknown";
}

static void rebase(const fileInfo& info)
{
	// generate temp file name
	char realFilePath[PATH_MAX];
	if ( realpath(info.path, realFilePath) == NULL ) {
		throwf("realpath() failed on %s, errno=%d", info.path, errno);
	}
	
	try {
		// rebase temp file
		MultiArchRebaser mar(realFilePath, true);
		const std::vector<AbstractRebaser*>&	rebasers = mar.getArchs();
		for(auto fait=info.archs.begin(); fait != info.archs.end(); ++fait) {
			for(auto rit=rebasers.begin(); rit != rebasers.end(); ++rit) {
				if ( (*rit)->getArchitecture() == fait->arch ) {
					(*rit)->rebase();
				}
			}	
		}
	}
	catch (const char* msg) {
		// throw exception with file name added
		const char* newMsg;
		asprintf((char**)&newMsg, "%s for file %s", msg, info.path);
		throw newMsg;
	}
}

static void usage()
{
	fprintf(stderr, "rebase [-v] [-arch <arch>] files...\n");
}


int main(int argc, const char* argv[])
{
	std::vector<fileInfo> files;
	std::set<cpu_type_t> onlyArchs;
	uint64_t lowAddress = 0;
	uint64_t highAddress = 0;

	try {
		// parse command line options
		char* endptr;
		for(int i=1; i < argc; ++i) {
			const char* arg = argv[i];
			if ( arg[0] == '-' ) {
				if ( strcmp(arg, "-v") == 0 ) {
					verbose = true;
				}
				else if ( strcmp(arg, "-arch") == 0 ) {
					const char* archName = argv[++i];
					if ( archName == NULL )
						throw "-arch missing architecture name";
					bool found = false;
					for (const ArchInfo* t=archInfoArray; t->archName != NULL; ++t) {
						if ( strcmp(t->archName,archName) == 0 ) {
							onlyArchs.insert(t->cpuType);
							found = true;
						}
					}
					if ( !found )
						throwf("unknown architecture %s", archName);
				}
				else {
					usage();
					throwf("unknown option: %s\n", arg);
				}
			}
			else {
				files.push_back(fileInfo(arg));
			}
		}
		
		if ( files.size() == 0 )
			throw "no files specified";
		
		// use all architectures if no restrictions specified
		if ( onlyArchs.size() == 0 ) {
			onlyArchs.insert(CPU_TYPE_POWERPC);
			onlyArchs.insert(CPU_TYPE_POWERPC64);
			onlyArchs.insert(CPU_TYPE_I386);
			onlyArchs.insert(CPU_TYPE_X86_64);
			onlyArchs.insert(CPU_TYPE_ARM);
		}
		
		// scan files and collect sizes
		for(std::vector<fileInfo>::iterator it=files.begin(); it != files.end(); ++it) {
			setSizes(*it, onlyArchs);
		}
		
		// rebase each file if it contains something rebaseable
		for(const auto fi : files) {
			if ( fi.archs.size() > 0 )
				rebase(fi);
		}
		
	}
	catch (const char* msg) {
		fprintf(stderr, "rebase failed: %s\n", msg);
		return 1;
	}
	
	return 0;
}



