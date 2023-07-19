package groth16

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	cudawrapper "github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
)

type OnDeviceData struct {
	p unsafe.Pointer
	size int
}

// Execute process in parallel the work function
func Execute(nbIterations int, work func(int, int), maxCpus ...int) {

	nbTasks := runtime.NumCPU()
	if len(maxCpus) == 1 {
		nbTasks = maxCpus[0]
		if nbTasks < 1 {
			nbTasks = 1
		} else if nbTasks > 512 {
			nbTasks = 512
		}
	}

	if nbTasks == 1 {
		// no go routines
		work(0, nbIterations)
		return
	}

	nbIterationsPerCpus := nbIterations / nbTasks

	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	var wg sync.WaitGroup

	extraTasks := nbIterations - (nbTasks * nbIterationsPerCpus)
	extraTasksOffset := 0

	for i := 0; i < nbTasks; i++ {
		wg.Add(1)
		_start := i*nbIterationsPerCpus + extraTasksOffset
		_end := _start + nbIterationsPerCpus
		if extraTasks > 0 {
			_end++
			extraTasks--
			extraTasksOffset++
		}
		go func() {
			work(_start, _end)
			wg.Done()
		}()
	}

	wg.Wait()
}

/*
* Adapters - these adapters convert between icicle and gnark
* todo: add conditional rendering
 */

func NttBN254GnarkAdapter(domain *fft.Domain, coset bool, scalars []fr.Element, isInverse bool, decimation int, deviceId int) []fr.Element {
	if coset && !isInverse {
		scale := func(cosetTable []fr.Element) {
			Execute(len(scalars), func(start, end int) {
				for i := start; i < end; i++ {
					scalars[i].Mul(&scalars[i], &cosetTable[i])
				}
			}, runtime.NumCPU())
		}
		if decimation == icicle.DIT {
			scale(domain.CosetTableReversed)
		} else {
			scale(domain.CosetTable)
		}
	}

	nttResult := icicle.BatchConvertFromFrGnark[icicle.ScalarField](scalars)
	icicle.NttBN254(&nttResult, isInverse, decimation, deviceId)

	if coset && isInverse {
		res := icicle.BatchConvertToFrGnark[icicle.ScalarField](nttResult)

		scale := func(cosetTable []fr.Element) {
			Execute(len(res), func(start, end int) {
				for i := start; i < end; i++ {
					res[i].Mul(&res[i], &cosetTable[i])
				}
			}, runtime.NumCPU())
		}
		if decimation == icicle.DIT {
			scale(domain.CosetTableInv)
		} else {
			scale(domain.CosetTableInvReversed)
		}

		return res
	}

	return icicle.BatchConvertToFrGnark[icicle.ScalarField](nttResult)
}

func INttOnDevice(scalars_d, twiddles_d, cosetPowers_d unsafe.Pointer, size, sizeBytes int, isCoset bool) (unsafe.Pointer, []time.Duration) {
	var timings []time.Duration	
	revTime := time.Now()
	icicle.ReverseScalars(scalars_d, size)
	revTimeElapsed := time.Since(revTime)
	timings = append(timings, revTimeElapsed)

	interpTime := time.Now()
	scalarsInterp := icicle.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)
	interpTimeElapsed := time.Since(interpTime)
	timings = append(timings, interpTimeElapsed)

	return scalarsInterp, timings
}

func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) ([]time.Duration) {
	var timings []time.Duration
	revTime := time.Now()
	if is_into {
		icicle.ToMontgomery(scalars_d, size)
	} else {
		icicle.FromMontgomery(scalars_d, size)
	}
	revTimeElapsed := time.Since(revTime)
	timings = append(timings, revTimeElapsed)

	return timings
}

func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) []time.Duration {
	var timings []time.Duration
	evalTime := time.Now()
	res := icicle.Evaluate(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)
	evalTimeElapsed := time.Since(evalTime)
	timings = append(timings, evalTimeElapsed)

	if res != 0 {
		fmt.Print("Issue evaluating")
	}

	revTime := time.Now()
	icicle.ReverseScalars(scalars_out, size)
	revTimeElapsed := time.Since(revTime)
	timings = append(timings, revTimeElapsed)

	return timings
}

func MsmBN254GnarkAdapter(points []curve.G1Affine, scalars []fr.Element) (curve.G1Jac, error, []time.Duration) {
	var timings []time.Duration
	out := new(icicle.PointBN254)

	convSTime := time.Now()
	parsedScalars := icicle.BatchConvertFromFrGnark[icicle.ScalarField](scalars)
	timings = append(timings, time.Since(convSTime))

	convPTime := time.Now()
	parsedPoints := icicle.BatchConvertFromG1Affine(points)
	timings = append(timings, time.Since(convPTime))

	msmTime := time.Now()
	_, err := icicle.MsmBN254(out, parsedPoints, parsedScalars, 0)
	timings = append(timings, time.Since(msmTime))

	return *out.ToGnarkJac(), err, timings
}


func PolyOps(a_d, b_d, c_d, den_d unsafe.Pointer, size int) (timings []time.Duration) {
	convSTime := time.Now()
	ret := icicle.VecScalarMulMod(a_d, b_d, size)
	timings = append(timings, time.Since(convSTime))

	if ret != 0 {
		fmt.Print("Vector mult a*b issue")
	}
	convSTime = time.Now()
	ret = icicle.VecScalarSub(a_d, c_d, size)
	timings = append(timings, time.Since(convSTime))

	if ret != 0 {
		fmt.Print("Vector sub issue")
	}
	convSTime = time.Now()
	ret = icicle.VecScalarMulMod(a_d, den_d, size)
	timings = append(timings, time.Since(convSTime))

	if ret != 0 {
		fmt.Print("Vector mult a*den issue")
	}
	
	return
}

func MsmOnDevice(scalars_d, points_d unsafe.Pointer, count, bucketFactor int, convert bool) (curve.G1Jac, unsafe.Pointer, error, time.Duration) {
	out_d, _ := cudawrapper.CudaMalloc(96)

	msmTime := time.Now()
	icicle.Commit(out_d, scalars_d, points_d, count, bucketFactor)
	timings := time.Since(msmTime)

	if convert {
		outHost := make([]icicle.PointBN254, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.PointBN254](outHost, out_d, 96)
		return *outHost[0].ToGnarkJac(), nil, nil, timings
	}

	return curve.G1Jac{}, out_d, nil, timings
}

func MsmG2OnDevice(scalars_d, points_d unsafe.Pointer, count, bucketFactor int, convert bool) (curve.G2Jac, unsafe.Pointer, error, time.Duration) {
	out_d, _ := cudawrapper.CudaMalloc(192)
	
	msmTime := time.Now()
	icicle.CommitG2(out_d, scalars_d, points_d, count, bucketFactor)
	timings := time.Since(msmTime)
	
	if convert {
		outHost := make([]icicle.G2Point, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.G2Point](outHost, out_d, 192)
		return *outHost[0].ToGnarkJac(), nil, nil, timings
	}

	return curve.G2Jac{}, out_d, nil, timings
}

func CopyToDevice(scalars []fr.Element, bytes int, copyDone chan unsafe.Pointer) {
	devicePtr, _ := cudawrapper.CudaMalloc(bytes)
	cudawrapper.CudaMemCpyHtoD[fr.Element](devicePtr, scalars, bytes)
	MontConvOnDevice(devicePtr, len(scalars), false)

	copyDone <- devicePtr
}
