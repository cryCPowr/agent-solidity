Pool fraction is not truncated when allocating the tokens allowing to receive more rewards than owed
Avatar for ABAIKUNANBAEV
ABAIKUNANBAEV

Medium

466d ago

Finding description and impact
At the moment, the function AllocateTokens() uses the Quo() operation when calculating the pool fraction for a particular validator pool. The problem is that it does not round down to 0 allowing to receive a bigger fraction than it actually is.

Proof of Concept
Let's take a look at how the operation is implemented:

https://github.com/initia-labs/initia/blob/main/x/distribution/keeper/allocation.go#L83

	poolFraction := rewardWeight.Weight.Quo(weightsSum)
Here, the rewardWeight is divided by the WeightsSum using the Quo() arithmetic and not QuoTruncate() that rounds the number down. The number is not truncated here as the Quo() function is used. The problem lies in the fact of how the Quo() method rounds the number:

Quo() - > calls chopPrecisionAndRound():

https://github.com/piplabs/cosmos-sdk/blob/7ce4a34e92b12fc3aed8eec6e080b6493554072d/math/dec.go#L356

func (d LegacyDec) QuoMut(d2 LegacyDec) LegacyDec {
	// multiply by precision twice
	d.i.Mul(d.i, squaredPrecisionReuse)
	d.i.Quo(d.i, d2.i)

	chopPrecisionAndRound(d.i)
	if d.i.BitLen() > maxDecBitLen {
		panic("Int overflow")
	}
	return d
}
QuoTruncate() (that should be used instead) -> calls chopPrecisionAndTruncate() under the hood:

https://github.com/piplabs/cosmos-sdk/blob/7ce4a34e92b12fc3aed8eec6e080b6493554072d/math/dec.go#L376

// mutable quotient truncate
func (d LegacyDec) QuoTruncateMut(d2 LegacyDec) LegacyDec {
	// multiply precision twice
	d.i.Mul(d.i, squaredPrecisionReuse)
	d.i.Quo(d.i, d2.i)

	chopPrecisionAndTruncate(d.i)
	if d.i.BitLen() > maxDecBitLen {
		panic("Int overflow")
	}
	return d
}


The method always rounds down and has to be used instead, otherwise, the users will get the bigger poolFraction and therefore bigger rewards. Take a look at the vanilla CosmosSDK implementation and how it rounds down the fractions:

https://github.com/cosmos/cosmos-sdk/blob/main/x/distribution/keeper/allocation.go#L71

powerFraction := math.LegacyNewDec(vote.Validator.Power).QuoTruncate(math.LegacyNewDec(totalPreviousPower))

Recommended mitigation steps
Use QuoTruncate() instead of Quo().

Links to affected code
allocation.go#L83Opens in a new window
Submissions touching same files
allocation.go
