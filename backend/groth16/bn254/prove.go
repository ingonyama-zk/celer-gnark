// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package groth16

import (
	"fmt"
	"math"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/logger"
	"math/big"
	"runtime"
	"time"
	"unsafe"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
	goicicle "github.com/ingonyama-zk/icicle/goicicle"
)

// Proof represents a Groth16 proof that was encoded with a ProvingKey and can be verified
// with a valid statement and a VerifyingKey
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type Proof struct {
	Ar, Krs                   curve.G1Affine
	Bs                        curve.G2Affine
	Commitment, CommitmentPok curve.G1Affine
}

// isValid ensures proof elements are in the correct subgroup
func (proof *Proof) isValid() bool {
	return proof.Ar.IsInSubGroup() && proof.Krs.IsInSubGroup() && proof.Bs.IsInSubGroup()
}

// CurveID returns the curveID
func (proof *Proof) CurveID() ecc.ID {
	return curve.ID
}

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, err
	}

	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Int("nbConstraints", len(r1cs.Constraints)).Str("backend", "groth16").Logger()

	proof := &Proof{}

	solverOpts := opt.SolverOpts[:len(opt.SolverOpts):len(opt.SolverOpts)]

	if r1cs.CommitmentInfo.Is() {
		solverOpts = append(solverOpts, solver.OverrideHint(r1cs.CommitmentInfo.HintID, func(_ *big.Int, in []*big.Int, out []*big.Int) error {
			// Perf-TODO: Converting these values to big.Int and back may be a performance bottleneck.
			// If that is the case, figure out a way to feed the solution vector into this function
			if len(in) != r1cs.CommitmentInfo.NbCommitted() { // TODO: Remove
				return fmt.Errorf("unexpected number of committed variables")
			}
			values := make([]fr.Element, r1cs.CommitmentInfo.NbPrivateCommitted)
			nbPublicCommitted := len(in) - len(values)
			inPrivate := in[nbPublicCommitted:]
			for i, inI := range inPrivate {
				values[i].SetBigInt(inI)
			}

			var err error
			proof.Commitment, proof.CommitmentPok, err = pk.CommitmentKey.Commit(values)
			if err != nil {
				return err
			}

			var res fr.Element
			res, err = solveCommitmentWire(&r1cs.CommitmentInfo, &proof.Commitment, in[:r1cs.CommitmentInfo.NbPublicCommitted()])
			res.BigInt(out[0])
			return err
		}))
	}

	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
	if err != nil {
		return nil, err
	}

	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)

	start := time.Now()

	// H (witness reduction / FFT part)
	var h unsafe.Pointer
	chHDone := make(chan struct{}, 1)
	go func() {
		h = computeH(solution.A, solution.B, solution.C, &pk.Domain)
		solution.A = nil
		solution.B = nil
		solution.C = nil
		chHDone <- struct{}{}
	}()

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesA, wireValuesB []fr.Element
	chWireValuesA, chWireValuesB := make(chan struct{}, 1), make(chan struct{}, 1)

	go func() {
		wireValuesA = make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
		for i, j := 0, 0; j < len(wireValuesA); i++ {
			if pk.InfinityA[i] {
				continue
			}
			wireValuesA[j] = wireValues[i]
			j++
		}
		close(chWireValuesA)
	}()
	go func() {
		wireValuesB = make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
		for i, j := 0, 0; j < len(wireValuesB); i++ {
			if pk.InfinityB[i] {
				continue
			}
			wireValuesB[j] = wireValues[i]
			j++
		}
		close(chWireValuesB)
	}()

	// sample random r and s
	var r, s big.Int
	var _r, _s, _kr fr.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, err
	}
	_kr.Mul(&_r, &_s).Neg(&_kr)

	_r.BigInt(&r)
	_s.BigInt(&s)

	// computes r[δ], s[δ], kr[δ]
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	var bs1, ar curve.G1Jac

	n := runtime.NumCPU()

	computeBS1 := func() {
		<-chWireValuesB

		pointsBytes := len(pk.G1.B)*64
		points_d, _ := goicicle.CudaMalloc(pointsBytes)
		parsedPoints := icicle.BatchConvertFromG1Affine(pk.G1.B)
		goicicle.CudaMemCpyHtoD[icicle.PointAffineNoInfinityBN254](points_d, parsedPoints, pointsBytes)
		

		scals := wireValuesB
		scalarBytes := len(scals)*32
		scalars_d, _ := goicicle.CudaMalloc(scalarBytes)
		scalarsIcicle := icicle.BatchConvertFromFrGnark[icicle.ScalarField](scals)
		goicicle.CudaMemCpyHtoD[icicle.ScalarField](scalars_d, scalarsIcicle, scalarBytes)
		
		icicleRes, _, _, time := MsmOnDevice(scalars_d, points_d, len(scals), true)
		log.Debug().Dur("took", time).Msg("Icicle API: MSM BS1 MSM")
		
		bs1 = icicleRes
		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])
	}

	computeAR1 := func() {
		<-chWireValuesA

		pointsBytes := len(pk.G1.A)*64
		points_d, _ := goicicle.CudaMalloc(pointsBytes)
		parsedPoints := icicle.BatchConvertFromG1Affine(pk.G1.A)
		goicicle.CudaMemCpyHtoD[icicle.PointAffineNoInfinityBN254](points_d, parsedPoints, pointsBytes)
		

		scals := wireValuesA
		scalarBytes := len(scals)*32
		scalars_d, _ := goicicle.CudaMalloc(scalarBytes)
		scalarsIcicle := icicle.BatchConvertFromFrGnark[icicle.ScalarField](scals)
		goicicle.CudaMemCpyHtoD[icicle.ScalarField](scalars_d, scalarsIcicle, scalarBytes)
		
		icicleRes, _, _, time := MsmOnDevice(scalars_d, points_d, len(scals), true)
		log.Debug().Dur("took", time).Msg("Icicle API: MSM AR1 MSM")
		
		ar = icicleRes
		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)
	}

	computeKRS := func() {
		// we could NOT split the Krs multiExp in 2, and just append pk.G1.K and pk.G1.Z
		// however, having similar lengths for our tasks helps with parallelism

		var krs, krs2, p1 curve.G1Jac
		sizeH := int(pk.Domain.Cardinality - 1) // comes from the fact the deg(H)=(n-1)+(n-1)-n=n-2
		
		pointsBytes := len(pk.G1.Z)*64
		points_d, _ := goicicle.CudaMalloc(pointsBytes)
		parsedPoints := icicle.BatchConvertFromG1Affine(pk.G1.Z)
		goicicle.CudaMemCpyHtoD[icicle.PointAffineNoInfinityBN254](points_d, parsedPoints, pointsBytes)

		icicleRes, _, _, time := MsmOnDevice(h, points_d, sizeH, true)

		log.Debug().Dur("took", time).Msg("Icicle API: MSM KRS2 MSM")
		
		krs2 = icicleRes
		// filter the wire values if needed;
		_wireValues := filter(wireValues, r1cs.CommitmentInfo.PrivateToPublic())

		pointsBytes = len(pk.G1.K)*64
		points_d, _ = goicicle.CudaMalloc(pointsBytes)
		parsedPoints = icicle.BatchConvertFromG1Affine(pk.G1.K)
		goicicle.CudaMemCpyHtoD[icicle.PointAffineNoInfinityBN254](points_d, parsedPoints, pointsBytes)
		

		scals := _wireValues[r1cs.GetNbPublicVariables():]
		scalarBytes := len(scals)*32
		scalars_d, _ := goicicle.CudaMalloc(scalarBytes)
		scalarsIcicle := icicle.BatchConvertFromFrGnark[icicle.ScalarField](scals)
		goicicle.CudaMemCpyHtoD[icicle.ScalarField](scalars_d, scalarsIcicle, scalarBytes)
		
		icicleRes, _, _, time = MsmOnDevice(scalars_d, points_d, len(scals), true)
		log.Debug().Dur("took", time).Msg("Icicle API: MSM KRS MSM")
		
		krs = icicleRes
		krs.AddMixed(&deltas[2])
		
		krs.AddAssign(&krs2)

		p1.ScalarMultiplication(&ar, &s)
		krs.AddAssign(&p1)

		p1.ScalarMultiplication(&bs1, &r)
		krs.AddAssign(&p1)

		proof.Krs.FromJacobian(&krs)
	}

	computeBS2 := func() error {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac

		nbTasks := n
		if nbTasks <= 16 {
			// if we don't have a lot of CPUs, this may artificially split the MSM
			nbTasks *= 2
		}
		<-chWireValuesB

		bsg2_time := time.Now()
		_, err := Bs.MultiExp(pk.G2.B, wireValuesB, ecc.MultiExpConfig{NbTasks: nbTasks})
		log.Debug().Dur("took", time.Since(bsg2_time)).Msg("Original API: MSM G2 BS")
		
		if err != nil {
			return err
		}

		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
		return nil
	}

	// wait for FFT to end, as it uses all our CPUs
	<-chHDone

	// schedule our proof part computations
	computeBS1()
	computeAR1()
	computeKRS()
	if err := computeBS2(); err != nil {
		return nil, err
	}

	log.Debug().Dur("took", time.Since(start)).Msg("prover done; TOTAL PROVE TIME")

	return proof, nil
}

// if len(toRemove) == 0, returns slice
// else, returns a new slice without the indexes in toRemove
// this assumes toRemove indexes are sorted and len(slice) > len(toRemove)
func filter(slice []fr.Element, toRemove []int) (r []fr.Element) {

	if len(toRemove) == 0 {
		return slice
	}
	r = make([]fr.Element, 0, len(slice)-len(toRemove))

	j := 0
	// note: we can optimize that for the likely case where len(slice) >>> len(toRemove)
	for i := 0; i < len(slice); i++ {
		if j < len(toRemove) && i == toRemove[j] {
			j++
			continue
		}
		r = append(r, slice[i])
	}

	return r
}

func computeH(a, b, c []fr.Element, domain *fft.Domain) unsafe.Pointer {
	// H part of Krs
	// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
	// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
	// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
	// 	3 - h = ifft_coset(ca o cb - cc)

	n := len(a)

	// add padding to ensure input length is domain cardinality
	padding := make([]fr.Element, int(domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)

	aCopy := make([]fr.Element, n)
	copy(aCopy, a)
	bCopy := make([]fr.Element, n)
	copy(bCopy, b)
	cCopy := make([]fr.Element, n)
	copy(cCopy, c)
	sizeBytes := n * fr.Bytes
	
	log := logger.Logger()

	/*********** BEGIN SETUP **********/
	om_selector := int(math.Log(float64(n)) / math.Log(2))
	start_twid := time.Now()
	twiddles_inv_d, twddles_err := icicle.GenerateTwiddles(n, om_selector, true)
	log.Debug().Dur("took", time.Since(start_twid)).Msg("Icicle API: Twiddles Inv")

	if twddles_err != nil {
		fmt.Print(twddles_err)
	}

	start_twid = time.Now()
	twiddles_d, twddles_err := icicle.GenerateTwiddles(n, om_selector, false)
	log.Debug().Dur("took", time.Since(start_twid)).Msg("Icicle API: Twiddles")
	
	start_cosetPower_api := time.Now()
	cosetPowers_d, _ := goicicle.CudaMalloc(sizeBytes)
	cosetTable := icicle.BatchConvertFromFrGnark[icicle.ScalarField](domain.CosetTable)
	goicicle.CudaMemCpyHtoD[icicle.ScalarField](cosetPowers_d, cosetTable, sizeBytes)
	log.Debug().Dur("took", time.Since(start_cosetPower_api)).Msg("Icicle API: Copy Coset")

	start_cosetPower_api = time.Now()
	cosetPowersInv_d, _ := goicicle.CudaMalloc(sizeBytes)
	cosetTableInv := icicle.BatchConvertFromFrGnark[icicle.ScalarField](domain.CosetTableInv)
	goicicle.CudaMemCpyHtoD[icicle.ScalarField](cosetPowersInv_d, cosetTableInv, sizeBytes)
	log.Debug().Dur("took", time.Since(start_cosetPower_api)).Msg("Icicle API: Copy Coset Inv")

	var denI, oneI fr.Element
	oneI.SetOne()
	denI.Exp(domain.FrMultiplicativeGen, big.NewInt(int64(domain.Cardinality)))
	denI.Sub(&denI, &oneI).Inverse(&denI)

	den_d, _ := goicicle.CudaMalloc(sizeBytes)
	log2Size := int(math.Floor(math.Log2(float64(n))))
	denIcicle := *icicle.NewFieldFromFrGnark[icicle.ScalarField](denI)
	denIcicleArr := []icicle.ScalarField{denIcicle}
	for i := 0; i < log2Size; i++ {
		denIcicleArr = append(denIcicleArr, denIcicleArr...)
	}
	for i := 0; i < (n - int(math.Pow(2, float64(log2Size)))); i++ {
		denIcicleArr = append(denIcicleArr, denIcicle)
	}

	goicicle.CudaMemCpyHtoD[icicle.ScalarField](den_d, denIcicleArr, sizeBytes)

	/*********** END SETUP **********/

	/*********** Copy a,b,c to Device Start ************/
	computeHTime := time.Now()
	copyADone := make(chan unsafe.Pointer, 1)
	copyBDone := make(chan unsafe.Pointer, 1)
	copyCDone := make(chan unsafe.Pointer, 1)
	copyToDevice := func (scalars []fr.Element, copyDone chan unsafe.Pointer) {
		a_device, _ := goicicle.CudaMalloc(sizeBytes)
		//(*C.BN254_scalar_t)
		//scalarsIcicleA := icicle.BatchConvertFromFrGnarkMontThreaded[icicle.ScalarField](scalars, 7)
		goicicle.CudaMemCpyHtoD[fr.Element](a_device, scalars, sizeBytes)
		//icicle.FromMontgomery(a_device, len(scalarsIcicleA))
		MontConvOnDevice(a_device, len(scalars), false)
		copyDone <- a_device
	}

	convTime := time.Now()
	go copyToDevice(a, copyADone)
	go copyToDevice(b, copyBDone)
	go copyToDevice(c, copyCDone)

	a_device := <- copyADone
	b_device := <- copyBDone
	c_device := <- copyCDone

	log.Debug().Dur("took", time.Since(convTime)).Msg("Icicle API: Conv and Copy a,b,c")
	/*********** Copy a,b,c to Device End ************/
	
	computeInttNttDone := make(chan error, 1)
	computeInttNttOnDevice := func (devicePointer unsafe.Pointer) {
		a_intt_d, timings_a := INttOnDevice(devicePointer, twiddles_inv_d, nil, n, sizeBytes, false)
		log.Debug().Dur("took", timings_a[0]).Msg("Icicle API: INTT Reverse")
		log.Debug().Dur("took", timings_a[1]).Msg("Icicle API: INTT Interp")
		
		timing_a2 := NttOnDevice(devicePointer, a_intt_d, twiddles_d, cosetPowers_d, n, n, sizeBytes, true)
		log.Debug().Dur("took", timing_a2[1]).Msg("Icicle API: NTT Coset Reverse")
		log.Debug().Dur("took", timing_a2[0]).Msg("Icicle API: NTT Coset Eval")

		computeInttNttDone <- nil
	}

	computeInttNttTime := time.Now()
	go computeInttNttOnDevice(a_device)
	go computeInttNttOnDevice(b_device)
	go computeInttNttOnDevice(c_device)
	_, _, _ = <- computeInttNttDone, <- computeInttNttDone, <- computeInttNttDone
	log.Debug().Dur("took", time.Since(computeInttNttTime)).Msg("Icicle API: INTT and NTT")

	poltime := PolyOps(a_device, b_device, c_device, den_d, n)
	log.Debug().Dur("took", poltime[0]).Msg("Icicle API: PolyOps Mul a b")
	log.Debug().Dur("took", poltime[1]).Msg("Icicle API: PolyOps Sub a c")
	log.Debug().Dur("took", poltime[2]).Msg("Icicle API: PolyOps Mul a den")

	h, timings_final := INttOnDevice(a_device, twiddles_inv_d, cosetPowersInv_d, n, sizeBytes, true)
	log.Debug().Dur("took", timings_final[0]).Msg("Icicle API: INTT Coset Reverse")
	log.Debug().Dur("took", timings_final[1]).Msg("Icicle API: INTT Coset Interp")
	
	icicle.ReverseScalars(h, n)
	log.Debug().Dur("took", time.Since(computeHTime)).Msg("Icicle API: computeH")
	
	return h
}
