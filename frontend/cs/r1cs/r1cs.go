/*
Copyright © 2021 ConsenSys Software Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package r1cs

import (
	"errors"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/schema"
)

func NewCompiler(curve ecc.ID) (frontend.Builder, error) {
	return newR1CS(curve), nil
}

type r1CS struct {
	compiled.ConstraintSystem
	Constraints []compiled.R1C

	st cs.CoeffTable

	// map for recording boolean constrained variables (to not constrain them twice)
	mtBooleans map[uint64][]compiled.LinearExpression
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newR1CS(curveID ecc.ID, initialCapacity ...int) *r1CS {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	system := r1CS{
		ConstraintSystem: compiled.ConstraintSystem{

			MDebug: make(map[int]int),
			MHints: make(map[int]*compiled.Hint),
		},
		Constraints: make([]compiled.R1C, 0, capacity),
		st:          cs.NewCoeffTable(),
		mtBooleans:  make(map[uint64][]compiled.LinearExpression),
	}

	system.st.Coeffs[compiled.CoeffIdZero].SetInt64(0)
	system.st.Coeffs[compiled.CoeffIdOne].SetInt64(1)
	system.st.Coeffs[compiled.CoeffIdTwo].SetInt64(2)
	system.st.Coeffs[compiled.CoeffIdMinusOne].SetInt64(-1)

	system.st.CoeffsIDsInt64[0] = compiled.CoeffIdZero
	system.st.CoeffsIDsInt64[1] = compiled.CoeffIdOne
	system.st.CoeffsIDsInt64[2] = compiled.CoeffIdTwo
	system.st.CoeffsIDsInt64[-1] = compiled.CoeffIdMinusOne

	system.Public = make([]string, 1)
	system.Secret = make([]string, 0)

	// by default the circuit is given a public wire equal to 1
	system.Public[0] = "one"

	system.CurveID = curveID

	return &system
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (system *r1CS) newInternalVariable() compiled.Variable {
	idx := system.NbInternalVariables
	system.NbInternalVariables++
	return compiled.Variable{
		LinExp: compiled.LinearExpression{compiled.Pack(idx, compiled.CoeffIdOne, schema.Internal)},
	}
}

// AddPublicVariable creates a new public Variable
func (system *r1CS) AddPublicVariable(name string) frontend.Variable {
	if system.Schema != nil {
		panic("do not call AddPublicVariable in circuit.Define()")
	}
	idx := len(system.Public)
	system.Public = append(system.Public, name)
	res := compiled.Variable{
		LinExp: compiled.LinearExpression{compiled.Pack(idx, compiled.CoeffIdOne, schema.Public)},
	}
	return res
}

// AddSecretVariable creates a new secret Variable
func (system *r1CS) AddSecretVariable(name string) frontend.Variable {
	if system.Schema != nil {
		panic("do not call AddSecretVariable in circuit.Define()")
	}
	idx := len(system.Secret)
	system.Secret = append(system.Secret, name)
	res := compiled.Variable{
		LinExp: compiled.LinearExpression{compiled.Pack(idx, compiled.CoeffIdOne, schema.Secret)},
	}
	return res
}

func (system *r1CS) one() compiled.Variable {
	return compiled.Variable{
		LinExp: compiled.LinearExpression{compiled.Pack(0, compiled.CoeffIdOne, schema.Public)},
	}
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public∥secret∥internal∥unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (system *r1CS) reduce(l compiled.Variable) compiled.Variable {
	// ensure our linear expression is sorted, by visibility and by Variable ID
	if !sort.IsSorted(l.LinExp) { // may not help
		sort.Sort(l.LinExp)
	}

	mod := system.CurveID.Info().Fr.Modulus()
	c := new(big.Int)
	for i := 1; i < len(l.LinExp); i++ {
		pcID, pvID, pVis := l.LinExp[i-1].Unpack()
		ccID, cvID, cVis := l.LinExp[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&system.st.Coeffs[pcID], &system.st.Coeffs[ccID])
			c.Mod(c, mod)
			l.LinExp[i-1].SetCoeffID(system.st.CoeffID(c))
			l.LinExp = append(l.LinExp[:i], l.LinExp[i+1:]...)
			i--
		}
	}
	return l
}

// newR1C clones the linear expression associated with the Variables (to avoid offseting the ID multiple time)
// and return a R1C
func newR1C(_l, _r, _o frontend.Variable) compiled.R1C {
	l := _l.(compiled.Variable)
	r := _r.(compiled.Variable)
	o := _o.(compiled.Variable)

	// interestingly, this is key to groth16 performance.
	// l * r == r * l == o
	// but the "l" linear expression is going to end up in the A matrix
	// the "r" linear expression is going to end up in the B matrix
	// the less Variable we have appearing in the B matrix, the more likely groth16.Setup
	// is going to produce infinity points in pk.G1.B and pk.G2.B, which will speed up proving time
	if len(l.LinExp) > len(r.LinExp) {
		l, r = r, l
	}

	return compiled.R1C{L: l.Clone(), R: r.Clone(), O: o.Clone()}
}

func (system *r1CS) addConstraint(r1c compiled.R1C, debugID ...int) {
	system.Constraints = append(system.Constraints, r1c)
	if len(debugID) > 0 {
		system.MDebug[len(system.Constraints)-1] = debugID[0]
	}
}

// Term packs a Variable and a coeff in a Term and returns it.
// func (system *R1CSRefactor) setCoeff(v Variable, coeff *big.Int) Term {
func (system *r1CS) setCoeff(v compiled.Term, coeff *big.Int) compiled.Term {
	_, vID, vVis := v.Unpack()
	return compiled.Pack(vID, system.st.CoeffID(coeff), vVis)
}

// MarkBoolean sets (but do not **constraint**!) v to be boolean
// This is useful in scenarios where a variable is known to be boolean through a constraint
// that is not api.AssertIsBoolean. If v is a constant, this is a no-op.
func (system *r1CS) MarkBoolean(v frontend.Variable) {
	if _, ok := system.ConstantValue(v); ok {
		return
	}
	// v is a linear expression
	l := v.(compiled.Variable).LinExp
	if !sort.IsSorted(l) {
		sort.Sort(l)
	}

	key := l.HashCode()
	list := system.mtBooleans[key]
	list = append(list, l)
	system.mtBooleans[key] = list
}

// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
// Use with care; variable may not have been **constrained** to be boolean
// This returns true if the v is a constant and v == 0 || v == 1.
func (system *r1CS) IsBoolean(v frontend.Variable) bool {
	if b, ok := system.ConstantValue(v); ok {
		return b.IsUint64() && b.Uint64() <= 1
	}
	// v is a linear expression
	l := v.(compiled.Variable).LinExp
	if !sort.IsSorted(l) {
		sort.Sort(l)
	}

	key := l.HashCode()
	list, ok := system.mtBooleans[key]
	if !ok {
		return false
	}

	for _, v := range list {
		if v.Equal(l) {
			return true
		}
	}
	return false
}

// checkVariables perform post compilation checks on the Variables
//
// 1. checks that all user inputs are referenced in at least one constraint
// 2. checks that all hints are constrained
func (system *r1CS) checkVariables() error {

	// TODO @gbotrel add unit test for that.

	cptSecret := len(system.Secret)
	cptPublic := len(system.Public)
	cptHints := len(system.MHints)

	secretConstrained := make([]bool, cptSecret)
	publicConstrained := make([]bool, cptPublic)
	// one wire does not need to be constrained
	publicConstrained[0] = true
	cptPublic--

	mHintsConstrained := make(map[int]bool)

	// for each constraint, we check the linear expressions and mark our inputs / hints as constrained
	processLinearExpression := func(l compiled.Variable) {
		for _, t := range l.LinExp {
			if t.CoeffID() == compiled.CoeffIdZero {
				// ignore zero coefficient, as it does not constraint the Variable
				// though, we may want to flag that IF the Variable doesn't appear else where
				continue
			}
			visibility := t.VariableVisibility()
			vID := t.WireID()

			switch visibility {
			case schema.Public:
				if vID != 0 && !publicConstrained[vID] {
					publicConstrained[vID] = true
					cptPublic--
				}
			case schema.Secret:
				if !secretConstrained[vID] {
					secretConstrained[vID] = true
					cptSecret--
				}
			case schema.Internal:
				if _, ok := system.MHints[vID]; !mHintsConstrained[vID] && ok {
					mHintsConstrained[vID] = true
					cptHints--
				}
			}
		}
	}
	for _, r1c := range system.Constraints {
		processLinearExpression(r1c.L)
		processLinearExpression(r1c.R)
		processLinearExpression(r1c.O)

		if cptHints|cptSecret|cptPublic == 0 {
			return nil // we can stop.
		}

	}

	// something is a miss, we build the error string
	var sbb strings.Builder
	if cptSecret != 0 {
		sbb.WriteString(strconv.Itoa(cptSecret))
		sbb.WriteString(" unconstrained secret input(s):")
		sbb.WriteByte('\n')
		for i := 0; i < len(secretConstrained) && cptSecret != 0; i++ {
			if !secretConstrained[i] {
				sbb.WriteString(system.Secret[i])
				sbb.WriteByte('\n')
				cptSecret--
			}
		}
		sbb.WriteByte('\n')
	}

	if cptPublic != 0 {
		sbb.WriteString(strconv.Itoa(cptPublic))
		sbb.WriteString(" unconstrained public input(s):")
		sbb.WriteByte('\n')
		for i := 0; i < len(publicConstrained) && cptPublic != 0; i++ {
			if !publicConstrained[i] {
				sbb.WriteString(system.Public[i])
				sbb.WriteByte('\n')
				cptPublic--
			}
		}
		sbb.WriteByte('\n')
	}

	if cptHints != 0 {
		sbb.WriteString(strconv.Itoa(cptHints))
		sbb.WriteString(" unconstrained hints")
		sbb.WriteByte('\n')
		// TODO we may add more debug info here → idea, in NewHint, take the debug stack, and store in the hint map some
		// debugInfo to find where a hint was declared (and not constrained)
	}
	return errors.New(sbb.String())
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
