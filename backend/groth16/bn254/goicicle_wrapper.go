package groth16

import (
	"fmt"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	device "github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
)

func INttOnDevice(scalars_d, twiddles_d, cosetPowers_d unsafe.Pointer, size, sizeBytes int, isCoset bool) unsafe.Pointer {
	icicle.ReverseScalars(scalars_d, size)

	scalarsInterp := icicle.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)

	return scalarsInterp
}

func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) {

	res := icicle.Evaluate(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)
	if res != 0 {
		fmt.Print("Issue evaluating")
	}
	icicle.ReverseScalars(scalars_out, size)
}

func PolyOps(a_d, b_d, c_d, den_d unsafe.Pointer, size int) {
	ret := icicle.VecScalarMulMod(a_d, b_d, size)

	if ret != 0 {
		fmt.Print("Vector mult a*b issue")
	}
	ret = icicle.VecScalarSub(a_d, c_d, size)

	if ret != 0 {
		fmt.Print("Vector sub issue")
	}
	ret = icicle.VecScalarMulMod(a_d, den_d, size)

	if ret != 0 {
		fmt.Print("Vector mult a*den issue")
	}
}

func MsmOnDevice(scalars_d, points_d unsafe.Pointer, count int, convert bool) (curve.G1Jac, unsafe.Pointer, error) {
	out_d, _ := device.CudaMalloc(96)

	icicle.Commit(out_d, scalars_d, points_d, count)

	if convert {
		outHost := make([]icicle.PointBN254, 1)
		device.CudaMemCpyDtoH[icicle.PointBN254](outHost, out_d, 96)
		return *outHost[0].ToGnarkJac(), nil, nil
	}

	return curve.G1Jac{}, out_d, nil

}
