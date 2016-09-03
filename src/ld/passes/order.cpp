/* -*- mode: C++; c-basic-offset: 4; tab-width: 4 -*-
 *
 * Copyright (c) 2009-2011 Apple Inc. All rights reserved.
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


#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <dlfcn.h>
#include <mach/machine.h>

#include <vector>
#include <map>
#include <set>
#include <unordered_map>

#include "ld.hpp"
#include "order.h"

namespace ld {
namespace passes {
namespace order {

//
// The purpose of this pass is to take the graph of all Atoms and produce an ordered
// sequence of atoms.  The constraints are that: 1) all Atoms of the same Segment must
// be contiguous, 2)  all Atoms of the same Section must be contigous, 3) Atoms specified
// in an order are sequenced as in the order file and before Atoms not specified,
// 4) Atoms in the same section from the same .o file should be contiguous and sequenced
// in the same order they were in the .o file, 5) Atoms in the same Section but which came
// from different .o files should be sequenced in the same order that the .o files
// were passed to the linker (i.e. command line order).
//
// The way this is implemented is that the linker passes a "base ordinal" to each File
// as it is constructed. Add each atom has an objectAddress() method. Then
// sorting is just sorting by section, then by file ordinal, then by object address.
//
// If an -order_file is specified, it gets more complicated.  First, an override-ordinal map
// is created.  It causes the sort routine to ignore the value returned by ordinal() and objectAddress() 
// and use the override value instead.  Next some Atoms must be laid out consecutively
// (e.g. hand written assembly that does not end with return, but rather falls into
// the next label).  This is modeled in via a kindNoneFollowOn fixup.  The use of
// kindNoneFollowOn fixups produces "clusters" of atoms that must stay together.
// If an order_file tries to move one atom, it may need to move a whole cluster.  The
// algorithm to do this models clusters using two maps.  The "starts" maps maps any
// atom in a cluster to the first Atom in the cluster.  The "nexts" maps an Atom in a
// cluster to the next Atom in the cluster.  With this in place, while processing an
// order_file, if any entry is in a cluster (in "starts" map), then the entire cluster is
// given ordinal overrides.
//

class Layout
{
public:
				Layout(const Options& opts, ld::Internal& state);
	void		doPass();
private:

	class Comparer {
	public:
					Comparer(const Layout& l, ld::Internal& s) : _layout(l), _state(s) {}
		bool		operator()(const ld::Atom* left, const ld::Atom* right);
	private:
		const Layout&	_layout;
		ld::Internal&	_state;
	};
				
	typedef std::unordered_map<const char*, const ld::Atom*, CStringHash, CStringEquals> NameToAtom;
	
	typedef std::map<const ld::Atom*, const ld::Atom*> AtomToAtom;
	
	typedef std::map<const ld::Atom*, uint32_t> AtomToOrdinal;

	const ld::Atom*		findAtom(const Options::OrderedSymbol& orderedSymbol);
	void				buildNameTable();
	void				buildFollowOnTables();
	void				buildOrdinalOverrideMap();
	const ld::Atom*		follower(const ld::Atom* atom);
	static bool			matchesObjectFile(const ld::Atom* atom, const char* objectFileLeafName);
			bool		possibleToOrder(const ld::Internal::FinalSection*);
	
	bool setsTarget(ld::Fixup::Kind kind);
	bool isStore(ld::Fixup::Kind kind);

	void buildRebasedAtoms();
	bool isPcRelStore(ld::Fixup::Kind kind);
	void noteRebaseInfo(ld::Internal& state,  ld::Internal::FinalSection* sect, const ld::Atom* atom,
							 ld::Fixup* fixupWithTarget, ld::Fixup* fixupWithMinusTarget, ld::Fixup* fixupWithStore,
							 const ld::Atom* target, const ld::Atom* minusTarget,
					 uint64_t targetAddend, uint64_t minusTargetAddend);

	const Options&						_options;
	ld::Internal&						_state;
	AtomToAtom							_followOnStarts;
	AtomToAtom							_followOnNexts;
	NameToAtom							_nameTable;
	std::vector<const ld::Atom*>		_nameCollisionAtoms;
	AtomToOrdinal						_ordinalOverrideMap;
	Comparer							_comparer;
	bool								_haveOrderFile;
	std::set<const ld::Atom*>			_rebasedAtoms;
	bool								_compactRebaseInfo;

	static bool							_s_log;
};

bool Layout::_s_log = false;

Layout::Layout(const Options& opts, ld::Internal& state)
	: _options(opts), _state(state), _comparer(*this, state), _haveOrderFile(opts.orderedSymbolsCount() != 0), _compactRebaseInfo(false)
{
}

bool Layout::isPcRelStore(ld::Fixup::Kind kind)
{
	switch ( kind ) {
		case ld::Fixup::kindStoreX86BranchPCRel8:
		case ld::Fixup::kindStoreX86BranchPCRel32:
		case ld::Fixup::kindStoreX86PCRel8:
		case ld::Fixup::kindStoreX86PCRel16:
		case ld::Fixup::kindStoreX86PCRel32:
		case ld::Fixup::kindStoreX86PCRel32_1:
		case ld::Fixup::kindStoreX86PCRel32_2:
		case ld::Fixup::kindStoreX86PCRel32_4:
		case ld::Fixup::kindStoreX86PCRel32GOTLoad:
		case ld::Fixup::kindStoreX86PCRel32GOTLoadNowLEA:
		case ld::Fixup::kindStoreX86PCRel32GOT:
		case ld::Fixup::kindStoreX86PCRel32TLVLoad:
		case ld::Fixup::kindStoreX86PCRel32TLVLoadNowLEA:
		case ld::Fixup::kindStoreARMBranch24:
		case ld::Fixup::kindStoreThumbBranch22:
		case ld::Fixup::kindStoreARMLoad12:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32GOTLoad:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32GOTLoadNowLEA:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32TLVLoad:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32TLVLoadNowLEA:
		case ld::Fixup::kindStoreTargetAddressARMBranch24:
		case ld::Fixup::kindStoreTargetAddressThumbBranch22:
		case ld::Fixup::kindStoreTargetAddressARMLoad12:
#if SUPPORT_ARCH_arm64
		case ld::Fixup::kindStoreARM64Page21:
		case ld::Fixup::kindStoreARM64PageOff12:
		case ld::Fixup::kindStoreARM64GOTLoadPage21:
		case ld::Fixup::kindStoreARM64GOTLoadPageOff12:
		case ld::Fixup::kindStoreARM64GOTLeaPage21:
		case ld::Fixup::kindStoreARM64GOTLeaPageOff12:
		case ld::Fixup::kindStoreARM64TLVPLoadPage21:
		case ld::Fixup::kindStoreARM64TLVPLoadPageOff12:
		case ld::Fixup::kindStoreARM64TLVPLoadNowLeaPage21:
		case ld::Fixup::kindStoreARM64TLVPLoadNowLeaPageOff12:
		case ld::Fixup::kindStoreARM64PCRelToGOT:
		case ld::Fixup::kindStoreTargetAddressARM64Page21:
		case ld::Fixup::kindStoreTargetAddressARM64PageOff12:
		case ld::Fixup::kindStoreTargetAddressARM64GOTLoadPage21:
		case ld::Fixup::kindStoreTargetAddressARM64GOTLoadPageOff12:
		case ld::Fixup::kindStoreTargetAddressARM64GOTLeaPage21:
		case ld::Fixup::kindStoreTargetAddressARM64GOTLeaPageOff12:
		case ld::Fixup::kindStoreTargetAddressARM64TLVPLoadPage21:
		case ld::Fixup::kindStoreTargetAddressARM64TLVPLoadPageOff12:
		case ld::Fixup::kindStoreTargetAddressARM64TLVPLoadNowLeaPage21:
		case ld::Fixup::kindStoreTargetAddressARM64TLVPLoadNowLeaPageOff12:
#endif
			return true;
		case ld::Fixup::kindStoreTargetAddressX86BranchPCRel32:
#if SUPPORT_ARCH_arm64
		case ld::Fixup::kindStoreTargetAddressARM64Branch26:
#endif
			return (_options.outputKind() != Options::kKextBundle);
		default:
			break;
	}
	return false;
}

bool Layout::isStore(ld::Fixup::Kind kind)
{
	switch ( kind ) {
		case ld::Fixup::kindNone:
		case ld::Fixup::kindNoneFollowOn:
		case ld::Fixup::kindNoneGroupSubordinate:
		case ld::Fixup::kindNoneGroupSubordinateFDE:
		case ld::Fixup::kindNoneGroupSubordinateLSDA:
		case ld::Fixup::kindNoneGroupSubordinatePersonality:
		case ld::Fixup::kindSetTargetAddress:
		case ld::Fixup::kindSubtractTargetAddress:
		case ld::Fixup::kindAddAddend:
		case ld::Fixup::kindSubtractAddend:
		case ld::Fixup::kindSetTargetImageOffset:
		case ld::Fixup::kindSetTargetSectionOffset:
			return false;
		default:
			break;
	}
	return true;
}

bool Layout::setsTarget(ld::Fixup::Kind kind)
{
	switch ( kind ) {
		case ld::Fixup::kindSetTargetAddress:
		case ld::Fixup::kindLazyTarget:
		case ld::Fixup::kindStoreTargetAddressLittleEndian32:
		case ld::Fixup::kindStoreTargetAddressLittleEndian64:
		case ld::Fixup::kindStoreTargetAddressBigEndian32:
		case ld::Fixup::kindStoreTargetAddressBigEndian64:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32:
		case ld::Fixup::kindStoreTargetAddressX86BranchPCRel32:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32GOTLoad:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32GOTLoadNowLEA:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32TLVLoad:
		case ld::Fixup::kindStoreTargetAddressX86PCRel32TLVLoadNowLEA:
		case ld::Fixup::kindStoreTargetAddressX86Abs32TLVLoad:
		case ld::Fixup::kindStoreTargetAddressARMBranch24:
		case ld::Fixup::kindStoreTargetAddressThumbBranch22:
		case ld::Fixup::kindStoreTargetAddressARMLoad12:
#if SUPPORT_ARCH_arm64
		case ld::Fixup::kindStoreTargetAddressARM64Branch26:
		case ld::Fixup::kindStoreTargetAddressARM64Page21:
		case ld::Fixup::kindStoreTargetAddressARM64PageOff12:
		case ld::Fixup::kindStoreTargetAddressARM64GOTLoadPage21:
		case ld::Fixup::kindStoreTargetAddressARM64GOTLoadPageOff12:
		case ld::Fixup::kindStoreTargetAddressARM64GOTLeaPage21:
		case ld::Fixup::kindStoreTargetAddressARM64GOTLeaPageOff12:
		case ld::Fixup::kindStoreTargetAddressARM64TLVPLoadPage21:
		case ld::Fixup::kindStoreTargetAddressARM64TLVPLoadPageOff12:
		case ld::Fixup::kindStoreTargetAddressARM64TLVPLoadNowLeaPage21:
		case ld::Fixup::kindStoreTargetAddressARM64TLVPLoadNowLeaPageOff12:
#endif
			return true;
		case ld::Fixup::kindStoreX86DtraceCallSiteNop:
		case ld::Fixup::kindStoreX86DtraceIsEnableSiteClear:
		case ld::Fixup::kindStoreARMDtraceCallSiteNop:
		case ld::Fixup::kindStoreARMDtraceIsEnableSiteClear:
		case ld::Fixup::kindStoreARM64DtraceCallSiteNop:
		case ld::Fixup::kindStoreARM64DtraceIsEnableSiteClear:
		case ld::Fixup::kindStoreThumbDtraceCallSiteNop:
		case ld::Fixup::kindStoreThumbDtraceIsEnableSiteClear:
			return (_options.outputKind() == Options::kObjectFile);
		default:
			break;
	}
	return false;
}

void Layout::buildRebasedAtoms()
{
	for (std::vector<ld::Internal::FinalSection*>::iterator sit = _state.sections.begin(); sit != _state.sections.end(); ++sit) {
		ld::Internal::FinalSection* sect = *sit;

		for (std::vector<const ld::Atom*>::iterator ait = sect->atoms.begin(); ait != sect->atoms.end(); ++ait) {
			const ld::Atom*		atom = *ait;

			ld::Fixup*			fixupWithTarget = NULL;
			ld::Fixup*			fixupWithMinusTarget = NULL;
			ld::Fixup*			fixupWithStore = NULL;
			ld::Fixup*			fixupWithAddend = NULL;
			const ld::Atom*		target = NULL;
			const ld::Atom*		minusTarget = NULL;
			uint64_t			targetAddend = 0;
			uint64_t			minusTargetAddend = 0;
			for (ld::Fixup::iterator fit = atom->fixupsBegin(); fit != atom->fixupsEnd(); ++fit) {
				if ( fit->firstInCluster() ) {
					fixupWithTarget = NULL;
					fixupWithMinusTarget = NULL;
					fixupWithStore = NULL;
					target = NULL;
					minusTarget = NULL;
					targetAddend = 0;
					minusTargetAddend = 0;
				}
				if ( this->setsTarget(fit->kind) ) {
					switch ( fit->binding ) {
						case ld::Fixup::bindingNone:
						case ld::Fixup::bindingByNameUnbound:
							break;
						case ld::Fixup::bindingByContentBound:
						case ld::Fixup::bindingDirectlyBound:
							fixupWithTarget = fit;
							target = fit->u.target;
							break;
						case ld::Fixup::bindingsIndirectlyBound:
							fixupWithTarget = fit;
							target = _state.indirectBindingTable[fit->u.bindingIndex];
							break;
					}
					assert(target != NULL);
				}
				switch ( fit->kind ) {
					case ld::Fixup::kindAddAddend:
						targetAddend = fit->u.addend;
						fixupWithAddend = fit;
						break;
					case ld::Fixup::kindSubtractAddend:
						minusTargetAddend = fit->u.addend;
						fixupWithAddend = fit;
						break;
					case ld::Fixup::kindSubtractTargetAddress:
						switch ( fit->binding ) {
							case ld::Fixup::bindingNone:
							case ld::Fixup::bindingByNameUnbound:
								break;
							case ld::Fixup::bindingByContentBound:
							case ld::Fixup::bindingDirectlyBound:
								fixupWithMinusTarget = fit;
								minusTarget = fit->u.target;
								break;
							case ld::Fixup::bindingsIndirectlyBound:
								fixupWithMinusTarget = fit;
								minusTarget = _state.indirectBindingTable[fit->u.bindingIndex];
								break;
						}
						assert(minusTarget != NULL);
						break;
					case ld::Fixup::kindDataInCodeStartData:
					case ld::Fixup::kindDataInCodeStartJT8:
					case ld::Fixup::kindDataInCodeStartJT16:
					case ld::Fixup::kindDataInCodeStartJT32:
					case ld::Fixup::kindDataInCodeStartJTA32:
					case ld::Fixup::kindDataInCodeEnd:
						break;
					default:
						break;
				}
				if ( this->isStore(fit->kind) ) {
					fixupWithStore = fit;
				}
				if ( fit->lastInCluster() ) {
					if ( (fixupWithStore != NULL) && (target != NULL) ) {
						if ( _options.outputKind() != Options::kObjectFile ) {
							if ( _options.makeCompressedDyldInfo() ) {
								this->noteRebaseInfo(_state, sect, atom, fixupWithTarget, fixupWithMinusTarget, fixupWithStore,
												  target, minusTarget, targetAddend, minusTargetAddend);
							}
						}
					}
				}
			}
		}
	}
}


void Layout::noteRebaseInfo(ld::Internal& state,  ld::Internal::FinalSection* sect, const ld::Atom* atom,
							 ld::Fixup* fixupWithTarget, ld::Fixup* fixupWithMinusTarget, ld::Fixup* fixupWithStore,
							 const ld::Atom* target, const ld::Atom* minusTarget,
							 uint64_t targetAddend, uint64_t minusTargetAddend)
{
	if ( sect->isSectionHidden() )
		return;

	// no need to rebase or bind PCRel stores
	if ( this->isPcRelStore(fixupWithStore->kind) ) {
		// as long as target is in same linkage unit
		if ( (target == NULL) || (target->definition() != ld::Atom::definitionProxy) ) {
			// make sure target is not global and weak
			if ( (target->scope() == ld::Atom::scopeGlobal) && (target->combine() == ld::Atom::combineByName) && (target->definition() == ld::Atom::definitionRegular)) {
				if ( (atom->section().type() == ld::Section::typeCFI)
					|| (atom->section().type() == ld::Section::typeDtraceDOF)
					|| (atom->section().type() == ld::Section::typeUnwindInfo) ) {
					// ok for __eh_frame and __uwind_info to use pointer diffs to global weak symbols
					return;
				}
				// <rdar://problem/13700961> spurious warning when weak function has reference to itself
				if ( fixupWithTarget->binding == ld::Fixup::bindingDirectlyBound ) {
					// ok to ignore pc-rel references within a weak function to itself
					return;
				}
			}
			return;
		}
	}

	// no need to rebase or bind PIC internal pointer diff
	if ( minusTarget != NULL ) {
		// with pointer diffs, both need to be in same linkage unit
		assert(minusTarget->definition() != ld::Atom::definitionProxy);
		assert(target != NULL);
		assert(target->definition() != ld::Atom::definitionProxy);
		if ( target == minusTarget ) {
			// This is a compile time constant and could have been optimized away by compiler
			return;
		}

		// check if target of pointer-diff is global and weak
		if ( (target->scope() == ld::Atom::scopeGlobal) && (target->combine() == ld::Atom::combineByName) && (target->definition() == ld::Atom::definitionRegular) ) {
			if ( (atom->section().type() == ld::Section::typeCFI)
				|| (atom->section().type() == ld::Section::typeDtraceDOF)
				|| (atom->section().type() == ld::Section::typeUnwindInfo) ) {
				// ok for __eh_frame and __uwind_info to use pointer diffs to global weak symbols
				return;
			}
		}
		return;
	}

	// no need to rebase or bind an atom's references to itself if the output is not slidable
	if ( (atom == target) && !_options.outputSlidable() )
		return;

	// cluster has no target, so needs no rebasing or binding
	if ( target == NULL )
		return;

	bool inReadOnlySeg = ((_options.initialSegProtection(sect->segmentName()) & VM_PROT_WRITE) == 0);
	bool needsRebase = false;

	uint8_t	rebaseType = REBASE_TYPE_POINTER;

	// special case lazy pointers
	if ( fixupWithTarget->kind == ld::Fixup::kindLazyTarget ) {
		assert(fixupWithTarget->u.target == target);
		assert(addend == 0);
		// lazy dylib lazy pointers do not have any dyld info
		if ( atom->section().type() == ld::Section::typeLazyDylibPointer )
			return;
	}
	else {
		// everything except lazy pointers
		switch ( target->definition() ) {
			case ld::Atom::definitionProxy:
				break;
			case ld::Atom::definitionRegular:
			case ld::Atom::definitionTentative:
				// only slideable images need rebasing info
				if ( _options.outputSlidable() ) {
					needsRebase = true;
				}
				// references to internal symbol never need binding
				if ( target->scope() != ld::Atom::scopeGlobal )
					break;
				else if ( _options.outputKind() == Options::kDynamicExecutable ) {
					// in main executables, the only way regular symbols are indirected is if -interposable is used
					if ( _options.interposable(target->name()) ) {
						needsRebase = false;
					}
				}
				else {
					// for flat-namespace or interposable two-level-namespace
					// all references to exported symbols get indirected
					if ( (_options.nameSpace() != Options::kTwoLevelNameSpace) || _options.interposable(target->name()) ) {
						// <rdar://problem/5254468> no external relocs for flat objc classes
						if ( strncmp(target->name(), ".objc_class_", 12) == 0 )
							break;
						// no rebase info for references to global symbols that will have binding info
						needsRebase = false;
					}
				}
				break;
			case ld::Atom::definitionAbsolute:
				break;
		}
	}

	// <rdar://problem/13828711> if target is an import alias, use base of alias
	if ( target->isAlias() && (target->definition() == ld::Atom::definitionProxy) ) {
		for (ld::Fixup::iterator fit = target->fixupsBegin(), end=target->fixupsEnd(); fit != end; ++fit) {
			if ( fit->firstInCluster() ) {
				if ( fit->kind == ld::Fixup::kindNoneFollowOn ) {
					if ( fit->binding == ld::Fixup::bindingDirectlyBound ) {
						target = fit->u.target;
					}
				}
			}
		}
	}

	// record dyld info for this cluster
	if ( needsRebase ) {
		if ( inReadOnlySeg ) {
			rebaseType = REBASE_TYPE_TEXT_ABSOLUTE32;
		}
		_rebasedAtoms.insert(atom);
	}
}

bool Layout::Comparer::operator()(const ld::Atom* left, const ld::Atom* right)
{
	if ( left == right )
		return false;

	// magic section$start symbol always sorts to the start of its section
	if ( left->contentType() == ld::Atom::typeSectionStart )
		return true;
	if ( right->contentType() == ld::Atom::typeSectionStart )
		return false;

	// if an -order_file is specified, then sorting is altered to sort those symbols first
	if ( _layout._haveOrderFile ) {
		AtomToOrdinal::const_iterator leftPos  = _layout._ordinalOverrideMap.find(left);
		AtomToOrdinal::const_iterator rightPos = _layout._ordinalOverrideMap.find(right);
		AtomToOrdinal::const_iterator end = _layout._ordinalOverrideMap.end();
		if ( leftPos != end ) {
			if ( rightPos != end ) {
				// both left and right are overridden, so compare overridden ordinals
				return leftPos->second < rightPos->second;
			}
			else {
				// left is overridden and right is not, so left < right
				return true;
			}
		}
		else {
			if ( rightPos != end ) {
				// right is overridden and left is not, so right < left
				return false;
			}
			else {
				// neither are overridden, 
				// fall into default sorting below
			}
		}
	}

	if ( _layout._compactRebaseInfo ) {
		auto leftPos  = _layout._rebasedAtoms.find(left);
		auto rightPos = _layout._rebasedAtoms.find(right);
		auto end = _layout._rebasedAtoms.end();
		if ( leftPos != end ) {
			if ( rightPos != end ) {
				// both left and right are overridden
				// fall into default sorting below
			}
			else {
				// left is overridden and right is not, so left < right
				return true;
			}
		}
		else {
			if ( rightPos != end ) {
				// right is overridden and left is not, so right < left
				return false;
			}
			else {
				// neither are overridden,
				// fall into default sorting below
			}
		}
	}

	// magic section$end symbol always sorts to the end of its section
	if ( left->contentType() == ld::Atom::typeSectionEnd )
		return false;
	if ( right->contentType() == ld::Atom::typeSectionEnd )
		return true;

	// aliases sort before their target
	bool leftIsAlias = left->isAlias();
	if ( leftIsAlias ) {
		for (ld::Fixup::iterator fit=left->fixupsBegin(); fit != left->fixupsEnd(); ++fit) {
			const ld::Atom* target = NULL;
			if ( fit->kind == ld::Fixup::kindNoneFollowOn ) {
				switch ( fit->binding ) {
					case ld::Fixup::bindingsIndirectlyBound:
						target = _state.indirectBindingTable[fit->u.bindingIndex];
						break;
					case ld::Fixup::bindingDirectlyBound:
						target = fit->u.target;
						break;
                    default:
                        break;   
				}
			    if ( target == right )
					return true; // left already before right
				left = target; // sort as if alias was its target
				break;
		    }
		}
	}
	bool rightIsAlias = right->isAlias();
    if ( rightIsAlias ) {
        for (ld::Fixup::iterator fit=right->fixupsBegin(); fit != right->fixupsEnd(); ++fit) {
			const ld::Atom* target = NULL;
			if ( fit->kind == ld::Fixup::kindNoneFollowOn ) {
				switch ( fit->binding ) {
					case ld::Fixup::bindingsIndirectlyBound:
						target = _state.indirectBindingTable[fit->u.bindingIndex];
						break;
					case ld::Fixup::bindingDirectlyBound:
						target = fit->u.target;
						break;
                    default:
                        break;   
				}
			    if ( target == left )
                    return false; // need to swap, alias is after target
				right = target; // continue with sort as if right was target
                break;
			}       
		}
    }

	// the __common section can have real or tentative definitions
	// we want the real ones to sort before tentative ones
	bool leftIsTent  =  (left->definition() == ld::Atom::definitionTentative);
	bool rightIsTent =  (right->definition() == ld::Atom::definitionTentative);
	if ( leftIsTent != rightIsTent )
		return rightIsTent; 

#if 0	
	// initializers are auto sorted to start of section
	if ( !fInitializerSet.empty() ) {
		bool leftFirst  = (fInitializerSet.count(left) != 0);
		bool rightFirst = (fInitializerSet.count(right) != 0);
		if ( leftFirst != rightFirst ) 
			return leftFirst;
	}

	// terminators are auto sorted to end of section
	if ( !fTerminatorSet.empty() ) {
		bool leftLast  = (fTerminatorSet.count(left) != 0);
		bool rightLast = (fTerminatorSet.count(right) != 0);
		if ( leftLast != rightLast ) 
			return rightLast;
	}
#endif
	
	// sort by .o order
	const ld::File* leftFile = left->file();
	const ld::File* rightFile = right->file();
	// <rdar://problem/10830126> properly sort if on file is NULL and the other is not
	ld::File::Ordinal leftFileOrdinal = (leftFile != NULL) ? leftFile->ordinal() : ld::File::Ordinal::NullOrdinal();
	ld::File::Ordinal rightFileOrdinal = (rightFile != NULL) ? rightFile->ordinal() : ld::File::Ordinal::NullOrdinal();
	if ( leftFileOrdinal != rightFileOrdinal )
		return leftFileOrdinal< rightFileOrdinal;

	// tentative defintions have no address in .o file, they are traditionally laid out by name
	if ( leftIsTent && rightIsTent ) 
		return (strcmp(left->name(), right->name()) < 0);

	// lastly sort by atom address
	int64_t addrDiff = left->objectAddress() - right->objectAddress();
	if ( addrDiff == 0 ) {
		// have same address so one might be an alias, and aliases need to sort before target
		if ( leftIsAlias != rightIsAlias )
			return leftIsAlias;

		// both at same address, sort by name 
		return (strcmp(left->name(), right->name()) < 0);
	}
	return (addrDiff < 0);
}

bool Layout::matchesObjectFile(const ld::Atom* atom, const char* objectFileLeafName)
{
	if ( objectFileLeafName == NULL )
		return true;
	const char* atomFullPath = atom->file()->path();
	const char* lastSlash = strrchr(atomFullPath, '/');
	if ( lastSlash != NULL ) {
		if ( strcmp(&lastSlash[1], objectFileLeafName) == 0 )
			return true;
	}
	else {
		if ( strcmp(atomFullPath, objectFileLeafName) == 0 )
			return true;
	}
	return false;
}


bool Layout::possibleToOrder(const ld::Internal::FinalSection* sect)
{
	// atoms in only some sections can have order_file applied
	switch ( sect->type() ) {
		case ld::Section::typeUnclassified:
		case ld::Section::typeCode:
		case ld::Section::typeZeroFill:
			return true;
		case ld::Section::typeImportProxies:
			return false;
		default:
			// if section has command line aliases, then we must apply ordering so aliases layout before targets
			if ( _options.haveCmdLineAliases() ) {
				for (std::vector<const ld::Atom*>::const_iterator ait=sect->atoms.begin(); ait != sect->atoms.end(); ++ait) {
					const ld::Atom* atom = *ait;
					if ( atom->isAlias() )
						return true;
				}
			}
			break;
	}
	return false;
}

void Layout::buildNameTable()
{
	for (std::vector<ld::Internal::FinalSection*>::iterator sit=_state.sections.begin(); sit != _state.sections.end(); ++sit) {
		ld::Internal::FinalSection* sect = *sit;
		// some sections are not worth scanning for names
		if ( ! possibleToOrder(sect) )
			continue;
		for (std::vector<const ld::Atom*>::iterator ait=sect->atoms.begin(); ait != sect->atoms.end(); ++ait) {
			const ld::Atom* atom = *ait;
			if ( atom->symbolTableInclusion() == ld::Atom::symbolTableIn ) {
				const char* name = atom->name();
				if ( name != NULL) {
					// static function or data
					NameToAtom::iterator pos = _nameTable.find(name);
					if ( pos == _nameTable.end() )
						_nameTable[name] = atom;
					else {
						const ld::Atom* existing = _nameTable[name];
						if ( existing != NULL ) {
							_nameCollisionAtoms.push_back(existing);
							_nameTable[name] = NULL;	// collision, denote with NULL
						}
						_nameCollisionAtoms.push_back(atom);
					}
				}
			}
		}
	}
	if ( _s_log ) {
		fprintf(stderr, "buildNameTable() _nameTable:\n");
		for(NameToAtom::iterator it=_nameTable.begin(); it != _nameTable.end(); ++it)
			fprintf(stderr, "  %p <- %s\n", it->second, it->first);
		fprintf(stderr, "buildNameTable() _nameCollisionAtoms:\n");
		for(std::vector<const ld::Atom*>::iterator it=_nameCollisionAtoms.begin(); it != _nameCollisionAtoms.end(); ++it)
			fprintf(stderr, "  %p, %s\n", *it, (*it)->name());
	}
}


const ld::Atom* Layout::findAtom(const Options::OrderedSymbol& orderedSymbol)
{
	// look for name in _nameTable
	NameToAtom::iterator pos = _nameTable.find(orderedSymbol.symbolName);
	if ( pos != _nameTable.end() ) {
		if ( (pos->second != NULL) && matchesObjectFile(pos->second, orderedSymbol.objectFileName) ) {
			//fprintf(stderr, "found %s in hash table\n", orderedSymbol.symbolName);
			return pos->second;
		}
		if ( pos->second == NULL ) {
			// name is in hash table, but atom is NULL, so that means there are duplicates, so we use super slow way
			if ( ( orderedSymbol.objectFileName == NULL) && _options.printOrderFileStatistics() ) {
				warning("%s specified in order_file but it exists in multiple .o files. "
						"Prefix symbol with .o filename in order_file to disambiguate", orderedSymbol.symbolName);
			}
			for (std::vector<const ld::Atom*>::iterator it=_nameCollisionAtoms.begin(); it != _nameCollisionAtoms.end(); it++) {
				const ld::Atom* atom = *it;
				if ( strcmp(atom->name(), orderedSymbol.symbolName) == 0 ) {
					if ( matchesObjectFile(atom, orderedSymbol.objectFileName) ) {
						return atom;
					}
				}
			}
		}
	}
		
	return NULL;
}

const ld::Atom* Layout::follower(const ld::Atom* atom)
{
	for (const ld::Atom* a = _followOnStarts[atom]; a != NULL; a = _followOnNexts[a]) {
		assert(a != NULL);
		if ( _followOnNexts[a] == atom ) {
			return a;
		}
	}
	// no follower, first in chain
	return NULL;
}

void Layout::buildFollowOnTables()
{
	// if no -order_file, then skip building follow on table
	if ( ! _haveOrderFile )
		return;

	// first make a pass to find all follow-on references and build start/next maps
	// which are a way to represent clusters of atoms that must layout together
	for (std::vector<ld::Internal::FinalSection*>::iterator sit=_state.sections.begin(); sit != _state.sections.end(); ++sit) {
		ld::Internal::FinalSection* sect = *sit;
		if ( !possibleToOrder(sect) ) 
			continue;
		for (std::vector<const ld::Atom*>::iterator ait=sect->atoms.begin(); ait != sect->atoms.end(); ++ait) {
			const ld::Atom* atom = *ait;
			for (ld::Fixup::iterator fit = atom->fixupsBegin(), end=atom->fixupsEnd(); fit != end; ++fit) {
				if ( fit->kind == ld::Fixup::kindNoneFollowOn ) {
					assert(fit->binding == ld::Fixup::bindingDirectlyBound);
					const ld::Atom* followOnAtom = fit->u.target;
					if ( _s_log ) fprintf(stderr, "ref %p %s -> %p %s\n", atom, atom->name(), followOnAtom, followOnAtom->name());
					assert(_followOnNexts.count(atom) == 0);
					_followOnNexts[atom] = followOnAtom;
					if ( _followOnStarts.count(atom) == 0 ) {
						// first time atom has been seen, make it start of chain
						_followOnStarts[atom] = atom;
						if ( _s_log ) fprintf(stderr, "  start %s -> %s\n", atom->name(), atom->name());
					}
					if ( _followOnStarts.count(followOnAtom) == 0 ) {
						// first time followOnAtom has been seen, make atom start of chain
						_followOnStarts[followOnAtom] = _followOnStarts[atom];
						if ( _s_log ) fprintf(stderr, "  start %s -> %s\n", followOnAtom->name(), _followOnStarts[atom]->name());
					}
					else {
						if ( _followOnStarts[followOnAtom] == followOnAtom ) {
							// followOnAtom atom already start of another chain, hook together 
							// and change all to use atom as start
							const ld::Atom* a = followOnAtom;
							while ( true ) {
								assert(_followOnStarts[a] == followOnAtom);
								_followOnStarts[a] = _followOnStarts[atom];
								if ( _s_log ) fprintf(stderr, "  adjust start for %s -> %s\n", a->name(), _followOnStarts[atom]->name());
								AtomToAtom::iterator pos = _followOnNexts.find(a);
								if ( pos != _followOnNexts.end() )
									a = pos->second;
								else
									break;
							}
						}
						else {
							// attempt to insert atom into existing followOn chain
							const ld::Atom* curPrevToFollowOnAtom = this->follower(followOnAtom);
							assert(curPrevToFollowOnAtom != NULL);
							assert((atom->size() == 0) || (curPrevToFollowOnAtom->size() == 0));
							if ( atom->size() == 0 ) {
								// insert alias into existing chain right before followOnAtom
								_followOnNexts[curPrevToFollowOnAtom] = atom;
								_followOnNexts[atom] = followOnAtom;
								_followOnStarts[atom] = _followOnStarts[followOnAtom];
							}
							else {
								// insert real atom into existing chain right before alias of followOnAtom
								const ld::Atom* curPrevPrevToFollowOn = this->follower(curPrevToFollowOnAtom);
								if ( curPrevPrevToFollowOn == NULL ) {
									// nothing previous, so make this a start of a new chain
									_followOnNexts[atom] = curPrevToFollowOnAtom;
									for (const ld::Atom* a = atom; a != NULL; a = _followOnNexts[a]) {
										if ( _s_log ) fprintf(stderr, "  adjust start for %s -> %s\n", a->name(), atom->name());
										_followOnStarts[a] = atom;
									}
								}
								else {
									// is previous, insert into existing chain before previous
									_followOnNexts[curPrevPrevToFollowOn] = atom;
									_followOnNexts[atom] = curPrevToFollowOnAtom;
									_followOnStarts[atom] = _followOnStarts[curPrevToFollowOnAtom];
								}
							}
						}
					}
				}
			}
		}
	}

	if ( _s_log ) {
		for(AtomToAtom::iterator it = _followOnStarts.begin(); it != _followOnStarts.end(); ++it)
			fprintf(stderr, "start %s -> %s\n", it->first->name(), it->second->name());

		for(AtomToAtom::iterator it = _followOnNexts.begin(); it != _followOnNexts.end(); ++it)
			fprintf(stderr, "next %s -> %s\n", it->first->name(), (it->second != NULL) ? it->second->name() : "null");
	}
}


class InSet
{
public:
	InSet(const std::set<const ld::Atom*>& theSet) : _set(theSet)  {}

	bool operator()(const ld::Atom* atom) const {
		return ( _set.count(atom) != 0 );
	}
private:
	const std::set<const ld::Atom*>&  _set;
};


void Layout::buildOrdinalOverrideMap()
{
	// if no -order_file, then skip building override map
	if ( ! _haveOrderFile )
		return;

	// build fast name->atom table
	this->buildNameTable();

	// handle .o files that cannot have their atoms rearranged
	// with the start/next maps of follow-on atoms we can process the order file and produce override ordinals
	uint32_t index = 0;
	uint32_t matchCount = 0;
	std::set<const ld::Atom*> moveToData;
	for(Options::OrderedSymbolsIterator it = _options.orderedSymbolsBegin(); it != _options.orderedSymbolsEnd(); ++it) {
		const ld::Atom* atom = this->findAtom(*it);
		if ( atom != NULL ) {
			// <rdar://problem/8612550> When order file used on data, turn ordered zero fill symbols into zero data
			switch ( atom->section().type() ) {
				case ld::Section::typeZeroFill:
				case ld::Section::typeTentativeDefs:
					if ( atom->size() <= 512 ) {
						const char* dstSeg;
						bool wildCardMatch;
						const ld::File* f = atom->file();
						const char* path = (f != NULL) ? f->path() : NULL;
						if ( !_options.moveRwSymbol(atom->name(), path, dstSeg, wildCardMatch) )
							moveToData.insert(atom);
					}
					break;
				default:
					break;
			}
		
			AtomToAtom::iterator start = _followOnStarts.find(atom);
			if ( start != _followOnStarts.end() ) {
				// this symbol for the order file corresponds to an atom that is in a cluster that must lay out together
				for(const ld::Atom* nextAtom = start->second; nextAtom != NULL; nextAtom = _followOnNexts[nextAtom]) {
					AtomToOrdinal::iterator pos = _ordinalOverrideMap.find(nextAtom);
					if ( pos == _ordinalOverrideMap.end() ) {
						_ordinalOverrideMap[nextAtom] = index++;
						if (_s_log ) fprintf(stderr, "override ordinal %u assigned to %s in cluster from %s\n", index, nextAtom->name(), nextAtom->file()->path());
					}
					else {
						if (_s_log ) fprintf(stderr, "could not order %s as %u because it was already laid out earlier by %s as %u\n",
										atom->name(), index, _followOnStarts[atom]->name(), _ordinalOverrideMap[atom] );
					}
				}
			}
			else {
				_ordinalOverrideMap[atom] = index;
				if (_s_log ) fprintf(stderr, "override ordinal %u assigned to %s from %s\n", index, atom->name(), atom->file()->path());
			}
			++matchCount;
		}
		else {
			if ( _options.printOrderFileStatistics() ) {
				if ( it->objectFileName == NULL )
					warning("can't find match for order_file entry: %s", it->symbolName);
				else
					warning("can't find match for order_file entry: %s/%s", it->objectFileName, it->symbolName);
			}
		}
		 ++index;
	}
	if ( _options.printOrderFileStatistics() && (_options.orderedSymbolsCount() != matchCount) ) {
		warning("only %u out of %lu order_file symbols were applicable", matchCount, _options.orderedSymbolsCount() );
	}

	// <rdar://problem/8612550> When order file used on data, turn ordered zero fill symbols into zeroed data
	if ( ! moveToData.empty() ) {
		// <rdar://problem/14919139> only move zero fill symbols to __data if there is a __data section
		ld::Internal::FinalSection* dataSect = NULL;
		for (std::vector<ld::Internal::FinalSection*>::iterator sit=_state.sections.begin(); sit != _state.sections.end(); ++sit) {
			ld::Internal::FinalSection* sect = *sit;
			if ( sect->type() == ld::Section::typeUnclassified ) {
				if ( (strcmp(sect->sectionName(), "__data") == 0) && (strcmp(sect->segmentName(), "__DATA") == 0) )
					dataSect = sect;
			}
		}

		if ( dataSect != NULL ) {
			// add atoms to __data
			dataSect->atoms.insert(dataSect->atoms.end(), moveToData.begin(), moveToData.end());
			// remove atoms from original sections
			for (std::vector<ld::Internal::FinalSection*>::iterator sit=_state.sections.begin(); sit != _state.sections.end(); ++sit) {
				ld::Internal::FinalSection* sect = *sit;
				switch ( sect->type() ) {
					case ld::Section::typeZeroFill:
					case ld::Section::typeTentativeDefs:
						sect->atoms.erase(std::remove_if(sect->atoms.begin(), sect->atoms.end(), InSet(moveToData)), sect->atoms.end());
						break;
					default:
						break;
				}
			}
			// update atom-to-section map
			for (std::set<const ld::Atom*>::iterator it=moveToData.begin(); it != moveToData.end(); ++it) {
				_state.atomToSection[*it] = dataSect;
			}
		}
	}

}

void Layout::doPass()
{
	const bool log = false;
	if ( log ) {
		fprintf(stderr, "Unordered atoms:\n");
		for (std::vector<ld::Internal::FinalSection*>::iterator sit=_state.sections.begin(); sit != _state.sections.end(); ++sit) {
			ld::Internal::FinalSection* sect = *sit;
			for (std::vector<const ld::Atom*>::iterator ait=sect->atoms.begin(); ait != sect->atoms.end(); ++ait) {
				const ld::Atom* atom = *ait;
				fprintf(stderr, "\t%p\t%s\t%s\n", atom, sect->sectionName(), atom->name());
			}
		}
	}
	
	// handle .o files that cannot have their atoms rearranged
	this->buildFollowOnTables();

	// assign new ordinal value to all ordered atoms
	this->buildOrdinalOverrideMap();

	// record all atoms which will be rebased
	this->buildRebasedAtoms();

	// sort atoms in each section
	for (std::vector<ld::Internal::FinalSection*>::iterator sit=_state.sections.begin(); sit != _state.sections.end(); ++sit) {
		ld::Internal::FinalSection* sect = *sit;
		if ( sect->type() ==  ld::Section::typeTempAlias )
			continue;
		if ( log ) fprintf(stderr, "sorting section %s\n", sect->sectionName());
		std::sort(sect->atoms.begin(), sect->atoms.end(), _comparer);
	}

	if ( log ) {
		fprintf(stderr, "Sorted atoms:\n");
		for (std::vector<ld::Internal::FinalSection*>::iterator sit=_state.sections.begin(); sit != _state.sections.end(); ++sit) {
			ld::Internal::FinalSection* sect = *sit;
			for (std::vector<const ld::Atom*>::iterator ait=sect->atoms.begin(); ait != sect->atoms.end(); ++ait) {
				const ld::Atom* atom = *ait;
				fprintf(stderr, "\t%p\t%s\t%s\n", atom, sect->sectionName(), atom->name());
			}
		}
	}
}


void doPass(const Options& opts, ld::Internal& state)
{
	Layout layout(opts, state);
	layout.doPass();
}


} // namespace order_file
} // namespace passes 
} // namespace ld 
