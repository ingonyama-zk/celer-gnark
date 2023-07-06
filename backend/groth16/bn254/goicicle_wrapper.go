package groth16

import (
	"unsafe"
	"fmt"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
	cudawrapper "github.com/ingonyama-zk/icicle/goicicle"
)

func INttOnDevice(scalars []fr.Element, twiddles_d, cosetPowers_d unsafe.Pointer, size, sizeBytes int, isCoset bool) (unsafe.Pointer, unsafe.Pointer) {
	scalars_d, _ := cudawrapper.CudaMalloc(sizeBytes)
	scalarsIcicle := icicle.BatchConvertFromFrGnark[icicle.ScalarField](scalars)

	cudawrapper.CudaMemCpyHtoD[icicle.ScalarField](scalars_d, scalarsIcicle, sizeBytes)
	icicle.ReverseScalars(scalars_d, size)
	scalarsInterp := icicle.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)


	return scalarsInterp, scalars_d
}

func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) []fr.Element {
	res := icicle.Evaluate(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)

	if res != 0 {
		fmt.Print("Issue evaluating")
	}

	icicle.ReverseScalars(scalars_out, size)

	a_host := make([]icicle.ScalarField, size)
	cudawrapper.CudaMemCpyDtoH[icicle.ScalarField](a_host, scalars_out, size_bytes)
	a_host_converted := icicle.BatchConvertToFrGnark[icicle.ScalarField](a_host)

	return a_host_converted
}

func MsmBN254GnarkAdapter(points []curve.G1Affine, scalars []fr.Element) (curve.G1Jac, error) {
	out := new(icicle.PointBN254)
	parsedScalars := icicle.BatchConvertFromFrGnark[icicle.ScalarField](scalars)
	parsedPoints := icicle.BatchConvertFromG1Affine(points)
	_, err := icicle.MsmBN254(out, parsedPoints, parsedScalars, 0)

	return *out.ToGnarkJac(), err
}

func MsmOnDevice(scalars_d, points_d unsafe.Pointer, count int, convert bool) (curve.G1Jac, unsafe.Pointer, error) {
	out_d, _ := cudawrapper.CudaMalloc(96)
	icicle.Commit(out_d, scalars_d, points_d, count)

	if convert {
		outHost := make([]icicle.PointBN254, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.PointBN254](outHost, out_d, 96)
		return *outHost[0].ToGnarkJac(), nil, nil
	}

	return curve.G1Jac{}, out_d, nil

}
