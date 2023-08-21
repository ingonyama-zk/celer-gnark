package groth16

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	cudawrapper "github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bls12377"
	"github.com/ingonyama-zk/iciclegnark/curves/bls12377"
)

type OnDeviceData struct {
	p    unsafe.Pointer
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

func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) []time.Duration {
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

func MsmBls12377GnarkAdapter(points []curve.G1Affine, scalars []fr.Element) (curve.G1Jac, error, []time.Duration) {
	var timings []time.Duration
	out := new(icicle.G1ProjectivePoint)

	convSTime := time.Now()
	parsedScalars := bls12377.BatchConvertFromFrGnark(scalars)
	timings = append(timings, time.Since(convSTime))

	convPTime := time.Now()
	parsedPoints := bls12377.BatchConvertFromG1Affine(points)
	timings = append(timings, time.Since(convPTime))

	msmTime := time.Now()
	_, err := icicle.Msm(out, parsedPoints, parsedScalars, 0)
	timings = append(timings, time.Since(msmTime))

	return *bls12377.G1ProjectivePointToGnarkJac(out), err, timings
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
	g1ProjPointBytes := fp.Bytes * 3

	out_d, _ := cudawrapper.CudaMalloc(g1ProjPointBytes)

	msmTime := time.Now()
	icicle.Commit(out_d, scalars_d, points_d, count, bucketFactor)
	timings := time.Since(msmTime)

	if convert {
		outHost := make([]icicle.G1ProjectivePoint, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.G1ProjectivePoint](outHost, out_d, g1ProjPointBytes)
		return *bls12377.G1ProjectivePointToGnarkJac(&outHost[0]), nil, nil, timings
	}

	return curve.G1Jac{}, out_d, nil, timings
}

func MsmG2OnDevice(scalars_d, points_d unsafe.Pointer, count, bucketFactor int, convert bool) (curve.G2Jac, unsafe.Pointer, error, time.Duration) {
	g2ProjPointBytes := fp.Bytes * 6 // X,Y,Z each with A0, A1 of fp.Bytes
	out_d, _ := cudawrapper.CudaMalloc(g2ProjPointBytes)

	msmTime := time.Now()
	icicle.CommitG2(out_d, scalars_d, points_d, count, bucketFactor)
	timings := time.Since(msmTime)

	if convert {
		outHost := make([]icicle.G2Point, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.G2Point](outHost, out_d, g2ProjPointBytes)
		return *bls12377.G2PointToGnarkJac(&outHost[0]), nil, nil, timings
	}

	return curve.G2Jac{}, out_d, nil, timings
}

func CopyToDevice(scalars []fr.Element, bytes int, copyDone chan unsafe.Pointer) {
	devicePtr, _ := cudawrapper.CudaMalloc(bytes)
	cudawrapper.CudaMemCpyHtoD[fr.Element](devicePtr, scalars, bytes)
	MontConvOnDevice(devicePtr, len(scalars), false)

	copyDone <- devicePtr
}
