package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/babylonlabs-io/babylon/v4/x/costaking/types"
	ftypes "github.com/babylonlabs-io/babylon/v4/x/finality/types"
)

var _ ftypes.FinalityHooks = HookFinality{}

// Wrapper struct
type HookFinality struct {
	k Keeper
}

// AfterBtcDelegationUnbonded handles BTC delegation unbonding events.
// This hook is triggered when a BTC delegation is unbonded/removed from the system.
//
// Possible State Changes (previous -> current):
// - inactive -> active: no-op
// - active -> active: subtract ActiveSatoshis
// - active -> inactive: subtract ActiveSatoshis (there's no risk of double counting
// because the AfterBbnFpRemovedFromActiveSet hook gets the updated active sats amount)
// - inactive -> inactive: no-op
// More concisely if the FP was active in the previous set, we subtract the sats.
func (h HookFinality) AfterBtcDelegationUnbonded(ctx context.Context, fpAddr sdk.AccAddress, btcDelAddr sdk.AccAddress, isFpActiveInPrevSet, isFpActiveInCurrSet bool, sats uint64) error {
	if !isFpActiveInPrevSet {
		return nil
	}
	return h.k.costakerModified(ctx, btcDelAddr, func(rwdTracker *types.CostakerRewardsTracker) {
		rwdTracker.ActiveSatoshis = rwdTracker.ActiveSatoshis.SubRaw(int64(sats))
	})
}

// AfterBtcDelegationActivated handles BTC delegation activation events.
// This hook is triggered when a BTC delegation transitions from "created" to "activated" state.
//
// State Changes:
// - If FP is active in previous set: ActiveSatoshis += sats
// - Otherwise: No change (delegation goes to inactive pool via other mechanisms)
func (h HookFinality) AfterBtcDelegationActivated(ctx context.Context, fpAddr sdk.AccAddress, btcDelAddr sdk.AccAddress, isFpActiveInPrevSet, isFpActiveInCurrSet bool, sats uint64) error {
	if !isFpActiveInPrevSet {
		return nil
	}

	return h.k.costakerModified(ctx, btcDelAddr, func(rwdTracker *types.CostakerRewardsTracker) {
		rwdTracker.ActiveSatoshis = rwdTracker.ActiveSatoshis.AddRaw(int64(sats))
	})
}

// AfterBbnFpEntersActiveSet handles finality provider activation events.
// This hook is triggered when a finality provider transitions from inactive to active status.
// It updates all the BTC delegations to this FP from inactive to active, updated the satoshis and score of
// affected costakers.
//
// State Changes:
// - For each costaker delegated to this FP:
//   - ActiveSatoshis += delegated_amount
func (h HookFinality) AfterBbnFpEntersActiveSet(ctx context.Context, fpAddr sdk.AccAddress) error {
	return h.k.ictvK.IterateBTCDelegationSatsUpdated(ctx, fpAddr, func(del sdk.AccAddress, activeSats math.Int) error {
		return h.k.costakerModified(ctx, del, func(rwdTracker *types.CostakerRewardsTracker) {
			rwdTracker.ActiveSatoshis = rwdTracker.ActiveSatoshis.Add(activeSats)
		})
	})
}

// AfterBbnFpRemovedFromActiveSet handles finality provider deactivation events.
// This hook is triggered when a finality provider was active set in the previous
// voting power distribution cache and it is not in the active set in the current one.
//
//	State Changes:
//
// - For each costaker delegated to this FP:
//   - ActiveSatoshis -= delegated_amount
func (h HookFinality) AfterBbnFpRemovedFromActiveSet(ctx context.Context, fpAddr sdk.AccAddress) error {
	return h.k.ictvK.IterateBTCDelegationSatsUpdated(ctx, fpAddr, func(del sdk.AccAddress, activeSats math.Int) error {
		return h.k.costakerModified(ctx, del, func(rwdTracker *types.CostakerRewardsTracker) {
			rwdTracker.ActiveSatoshis = rwdTracker.ActiveSatoshis.Sub(activeSats)
		})
	})
}

// Create new distribution hooks
func (k Keeper) HookFinality() HookFinality {
	return HookFinality{k}
}
