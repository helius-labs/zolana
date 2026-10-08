package emfield

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() {
	solver.RegisterHint(PlainCheckHint, BalanceHint)
}

const maxFoldDigit = 16

type productKey struct {
	a, b  *Element
	point int
}

type plainState struct {
	foldDigits  []*big.Int
	foldRows    [][]*big.Int
	vinv        map[int][][]*big.Int
	products    map[productKey]frontend.Variable
	crt         *crtBasis
	crtDone     bool
	crtProducts map[productKey]frontend.Variable
}

func balancedDigits(v *big.Int, bits, n int) []*big.Int {
	base := pow2(bits)
	half := pow2(bits - 1)
	rest := new(big.Int).Set(v)
	out := make([]*big.Int, 0, n)
	for len(out) < n {
		d := new(big.Int).Mod(rest, base)
		if d.Cmp(half) > 0 {
			d.Sub(d, base)
		}
		out = append(out, d)
		rest.Sub(rest, d).Rsh(rest, uint(bits))
	}
	if rest.Sign() != 0 {
		return nil
	}
	return out
}

func newPlainState(f *Field) *plainState {
	s := &plainState{vinv: map[int][][]*big.Int{}, products: map[productKey]frontend.Variable{}, crtProducts: map[productKey]frontend.Variable{}}
	l := f.lay
	top := new(big.Int).Mod(pow2(l.LimbBits*l.NbLimbs), f.mod)
	digits := balancedDigits(top, l.LimbBits, l.NbLimbs)
	if digits == nil {
		return s
	}
	for _, d := range digits {
		if new(big.Int).Abs(d).Cmp(big.NewInt(maxFoldDigit)) > 0 {
			return s
		}
	}
	s.foldDigits = digits
	return s
}

func (s *plainState) fold(n, degree int) [][]*big.Int {
	if s.foldDigits == nil {
		return nil
	}
	for len(s.foldRows) <= degree {
		i := len(s.foldRows)
		row := make([]*big.Int, n)
		for j := range row {
			row[j] = new(big.Int)
		}
		if i < n {
			row[i].SetInt64(1)
		} else {
			prev := s.foldRows[i-1]
			for j := 1; j < n; j++ {
				row[j].Set(prev[j-1])
			}
			carry := prev[n-1]
			for j := range row {
				row[j].Add(row[j], new(big.Int).Mul(carry, s.foldDigits[j]))
			}
		}
		s.foldRows = append(s.foldRows, row)
	}
	return s.foldRows[:degree+1]
}

func evalPoint(k int) int64 {
	if k == 0 {
		return 0
	}
	if k%2 == 1 {
		return int64((k + 1) / 2)
	}
	return -int64(k / 2)
}

func (s *plainState) inverseVandermonde(degree int, q *big.Int) [][]*big.Int {
	if m, ok := s.vinv[degree]; ok {
		return m
	}
	n := degree + 1
	a := make([][]*big.Int, n)
	for k := range a {
		a[k] = make([]*big.Int, 2*n)
		x := big.NewInt(evalPoint(k))
		pw := big.NewInt(1)
		for i := 0; i < n; i++ {
			a[k][i] = new(big.Int).Mod(pw, q)
			pw = new(big.Int).Mul(pw, x)
		}
		for i := 0; i < n; i++ {
			a[k][n+i] = new(big.Int)
			if i == k {
				a[k][n+i].SetInt64(1)
			}
		}
	}
	for col := 0; col < n; col++ {
		pivot := -1
		for r := col; r < n; r++ {
			if a[r][col].Sign() != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			panic("singular evaluation points")
		}
		a[col], a[pivot] = a[pivot], a[col]
		inv := new(big.Int).ModInverse(a[col][col], q)
		for j := range a[col] {
			a[col][j].Mul(a[col][j], inv).Mod(a[col][j], q)
		}
		for r := 0; r < n; r++ {
			if r == col || a[r][col].Sign() == 0 {
				continue
			}
			factor := new(big.Int).Set(a[r][col])
			for j := range a[r] {
				a[r][j].Sub(a[r][j], new(big.Int).Mul(factor, a[col][j])).Mod(a[r][j], q)
			}
		}
	}
	out := make([][]*big.Int, n)
	for i := range out {
		out[i] = a[i][n:]
	}
	s.vinv[degree] = out
	return out
}

type linForm struct {
	vars   []frontend.Variable
	coefs  []*big.Int
	consts *big.Int
}

func newLinForm() *linForm {
	return &linForm{consts: new(big.Int)}
}

func (l *linForm) add(v frontend.Variable, c *big.Int) {
	if c.Sign() == 0 {
		return
	}
	l.vars = append(l.vars, v)
	l.coefs = append(l.coefs, new(big.Int).Set(c))
}

func (l *linForm) addConst(c *big.Int) {
	l.consts.Add(l.consts, c)
}

func (l *linForm) build(api frontend.API) frontend.Variable {
	q := api.Compiler().Field()
	acc := frontend.Variable(new(big.Int).Mod(l.consts, q))
	for i, v := range l.vars {
		acc = api.Add(acc, api.Mul(v, new(big.Int).Mod(l.coefs[i], q)))
	}
	return acc
}

func elementDegree(e *Element) int {
	return len(e.limbs) - 1
}

func (f *Field) evalAt(e *Element, x int64) frontend.Variable {
	acc := frontend.Variable(0)
	pw := big.NewInt(1)
	for _, l := range e.limbs {
		acc = f.api.Add(acc, f.api.Mul(l, new(big.Int).Set(pw)))
		pw.Mul(pw, big.NewInt(x))
	}
	return acc
}

func (f *Field) productAt(factors []*Element, k int) frontend.Variable {
	x := evalPoint(k)
	s := f.plain
	var acc frontend.Variable
	rest := factors
	if len(factors) >= 2 {
		key := productKey{factors[0], factors[1], k}
		if v, ok := s.products[key]; ok {
			acc = v
		} else if v, ok := s.products[productKey{factors[1], factors[0], k}]; ok {
			acc = v
		} else {
			acc = f.api.Mul(f.evalAt(factors[0], x), f.evalAt(factors[1], x))
			s.products[key] = acc
		}
		rest = factors[2:]
	}
	for _, e := range rest {
		acc = f.api.Mul(acc, f.evalAt(e, x))
	}
	return acc
}

func (f *Field) plainCheck(in []Term, withResult bool) *Element {
	api, lay := f.api, f.lay
	q := api.Compiler().Field()
	halfQ := new(big.Int).Rsh(q, 1)
	n, bits := lay.NbLimbs, lay.LimbBits

	terms := make([]term, len(in))
	var elems []*Element
	index := map[*Element]int{}
	for i, t := range in {
		terms[i] = term{coef: big.NewInt(t.Coef), factors: t.Factors}
		for _, e := range t.Factors {
			if _, ok := index[e]; !ok {
				index[e] = len(elems)
				elems = append(elems, e)
			}
		}
	}

	var coefAbs []*big.Int
	elo, ehi := new(big.Int), new(big.Int)
	for _, t := range terms {
		poly := []*big.Int{new(big.Int).Abs(t.coef)}
		for _, e := range t.factors {
			poly = polyMulAbs(poly, limbAbs(e))
		}
		coefAbs = addInto(coefAbs, poly)
		lo, hi := termRange(t)
		elo.Add(elo, lo)
		ehi.Add(ehi, hi)
	}
	for _, c := range coefAbs {
		if c.Cmp(halfQ) >= 0 {
			panic("product coefficient does not fit the native field")
		}
	}
	degree := len(coefAbs) - 1

	fold := f.plain.fold(n, degree)
	positions := len(coefAbs)
	vAbs := coefAbs
	vlo, vhi := elo, ehi
	if fold != nil {
		positions = n
		vAbs = make([]*big.Int, n)
		for j := range vAbs {
			vAbs[j] = new(big.Int)
			for i, c := range coefAbs {
				vAbs[j].Add(vAbs[j], new(big.Int).Mul(new(big.Int).Abs(fold[i][j]), c))
			}
			if vAbs[j].Cmp(halfQ) >= 0 {
				panic("folded coefficient does not fit the native field")
			}
		}
		total := new(big.Int)
		for j, c := range vAbs {
			total.Add(total, new(big.Int).Lsh(c, uint(bits*j)))
		}
		vlo, vhi = new(big.Int).Neg(total), total
	}

	rMax := new(big.Int)
	if withResult {
		rMax.Sub(pow2(f.modBits), big.NewInt(1))
	}
	kmin := floorDiv(new(big.Int).Sub(vlo, rMax), f.mod)
	kmax := floorDiv(vhi, f.mod)
	offset := new(big.Int)
	if kmin.Sign() < 0 {
		offset.Neg(kmin)
	}
	kBits := max(new(big.Int).Add(kmax, offset).BitLen(), 1)
	var kWidths []int
	if fold != nil {
		kWidths = []int{kBits}
	} else {
		kWidths = lay.splitWidths(kBits)
	}
	offsetLimbs := make([]*big.Int, len(kWidths))
	tmp := new(big.Int).Set(offset)
	for i, w := range kWidths {
		offsetLimbs[i] = new(big.Int).And(tmp, new(big.Int).Sub(pow2(w), big.NewInt(1)))
		tmp.Rsh(tmp, uint(w))
	}
	kAbs := make([]*big.Int, len(kWidths))
	for i, w := range kWidths {
		kAbs[i] = maxInt(offsetLimbs[i], new(big.Int).Sub(new(big.Int).Sub(pow2(w), big.NewInt(1)), offsetLimbs[i]))
	}

	wAbs := append([]*big.Int{}, vAbs...)
	for i := range wAbs {
		wAbs[i] = new(big.Int).Set(wAbs[i])
	}
	if withResult {
		rAbs := make([]*big.Int, len(f.widths))
		for i, w := range f.widths {
			rAbs[i] = new(big.Int).Sub(pow2(w), big.NewInt(1))
		}
		wAbs = addInto(wAbs, rAbs)
	}
	if len(kAbs) > 0 {
		wAbs = addInto(wAbs, polyMulAbs(kAbs, f.modLim))
	}
	positions = max(positions, len(wAbs))
	for len(wAbs) < positions {
		wAbs = append(wAbs, new(big.Int))
	}
	kSpan := maxInt(offset, new(big.Int).Sub(new(big.Int).Sub(pow2(kBits), big.NewInt(1)), offset))
	wMax := absMax(vlo, vhi)
	wMax.Add(wMax, rMax).Add(wMax, new(big.Int).Mul(kSpan, f.mod))
	m := 0
	for m < positions-1 && new(big.Int).Lsh(q, uint(bits*m)).Cmp(wMax) <= 0 {
		m++
	}
	full := new(big.Int).Lsh(q, uint(bits*m)).Cmp(wMax) <= 0

	var r *Element
	var kLimbs []frontend.Variable
	nbOut := 0
	if withResult {
		nbOut += lay.nbPiecesAll(f.widths)
	}
	if fold == nil {
		nbOut += lay.nbPiecesAll(kWidths)
	}
	if nbOut > 0 {
		inputs := lay.header()
		for _, l := range f.modLim {
			inputs = append(inputs, l)
		}
		hasR, hasK := 0, 0
		if withResult {
			hasR = 1
		}
		if fold == nil {
			hasK = 1
		}
		inputs = append(inputs, hasR, hasK, kBits)
		for _, o := range offsetLimbs {
			inputs = append(inputs, o)
		}
		inputs = append(inputs, len(terms))
		for _, t := range terms {
			inputs = append(inputs, t.coef, len(t.factors))
			for _, e := range t.factors {
				inputs = append(inputs, index[e])
			}
		}
		inputs = append(inputs, len(elems))
		for _, e := range elems {
			inputs = append(inputs, len(e.limbs))
			inputs = append(inputs, e.limbs...)
		}
		out, err := api.Compiler().NewHint(PlainCheckHint, nbOut, inputs...)
		if err != nil {
			panic(fmt.Sprintf("plain check hint: %v", err))
		}
		if withResult {
			r, out = f.fromPieces(out, f.widths)
		}
		if fold == nil {
			var k *Element
			k, _ = f.fromPieces(out, kWidths)
			kLimbs = k.limbs
		}
	}

	vForm := f.foldedForms(terms, degree, fold)

	var kExpr frontend.Variable
	if fold != nil {
		native := newLinForm()
		for j := 0; j < n; j++ {
			mergeForm(native, vForm(j), pow2(bits*j))
		}
		if withResult {
			for j, l := range r.limbs {
				native.add(l, new(big.Int).Neg(pow2(bits*j)))
			}
		}
		inv := new(big.Int).ModInverse(f.mod, q)
		k := native.build(api)
		kExpr = api.Mul(k, inv)
		f.rc.Check(api.Add(kExpr, offset), kBits)
	}

	wForm := func(pos int) *linForm {
		form := vForm(pos)
		if withResult && pos < len(r.limbs) {
			form.add(r.limbs[pos], big.NewInt(-1))
		}
		if fold != nil {
			if pos < len(f.modLim) {
				form.add(kExpr, new(big.Int).Neg(f.modLim[pos]))
			}
		} else {
			for a, kl := range kLimbs {
				b := pos - a
				if b < 0 || b >= len(f.modLim) {
					continue
				}
				form.add(kl, new(big.Int).Neg(f.modLim[b]))
				form.addConst(new(big.Int).Mul(offsetLimbs[a], f.modLim[b]))
			}
		}
		return form
	}

	if fold == nil && !full {
		native := newLinForm()
		for pos := 0; pos < positions; pos++ {
			mergeForm(native, wForm(pos), pow2(bits*pos))
		}
		api.AssertIsEqual(native.build(api), 0)
	}

	var carry frontend.Variable = 0
	prevBits := -1
	for pos := 0; pos < m; {
		start := pos
		gmax := new(big.Int)
		if prevBits >= 0 {
			gmax.Set(pow2(prevBits))
		}
		b := 0
		for pos < m {
			shift := bits * (pos + 1 - start)
			cand := new(big.Int).Add(gmax, new(big.Int).Lsh(wAbs[pos], uint(bits*(pos-start))))
			cb := new(big.Int).Rsh(cand, uint(shift)).BitLen()
			lift := new(big.Int).Add(cand, new(big.Int).Lsh(big.NewInt(1), uint(shift+cb)))
			if lift.Cmp(halfQ) >= 0 {
				break
			}
			gmax, b = cand, cb
			pos++
		}
		if pos == start {
			panic(fmt.Sprintf("carry %d does not lift", start))
		}
		group := newLinForm()
		for p := start; p < pos; p++ {
			mergeForm(group, wForm(p), pow2(bits*(p-start)))
		}
		sum := api.Add(group.build(api), carry)
		carry = api.Mul(sum, new(big.Int).ModInverse(pow2(bits*(pos-start)), q))
		f.rc.Check(api.Add(carry, pow2(b)), b+1)
		prevBits = b
	}
	if full {
		top := wForm(m).build(api)
		if new(big.Int).Add(wAbs[m], pow2(prevBits)).Cmp(halfQ) >= 0 {
			panic("top coefficient does not lift")
		}
		api.AssertIsEqual(api.Add(top, carry), 0)
	}
	return r
}

func mergeForm(dst, src *linForm, c *big.Int) {
	for i, v := range src.vars {
		dst.add(v, new(big.Int).Mul(src.coefs[i], c))
	}
	dst.addConst(new(big.Int).Mul(src.consts, c))
}

func (f *Field) foldedForms(terms []term, degree int, fold [][]*big.Int) func(j int) *linForm {
	q := f.api.Compiler().Field()
	n := f.lay.NbLimbs
	var crt *crtBasis
	if fold != nil {
		crt = f.plain.crtBasis(f, q)
	}
	coefForms := make([]*linForm, degree+1)
	for i := range coefForms {
		coefForms[i] = newLinForm()
	}
	var crtForms []*linForm
	for _, t := range terms {
		switch len(t.factors) {
		case 0:
			coefForms[0].addConst(t.coef)
			continue
		case 1:
			for i, l := range t.factors[0].limbs {
				coefForms[i].add(l, t.coef)
			}
			continue
		}
		if crt != nil && len(t.factors) == 2 && len(t.factors[0].limbs) == n && len(t.factors[1].limbs) == n {
			if crtForms == nil {
				crtForms = make([]*linForm, n)
				for j := range crtForms {
					crtForms[j] = newLinForm()
				}
			}
			for k := range crt.forms {
				w := f.crtProductAt(crt, t.factors[0], t.factors[1], k)
				for j, row := range crt.combine {
					crtForms[j].add(w, new(big.Int).Mul(t.coef, row[k]))
				}
			}
			continue
		}
		d := 0
		for _, e := range t.factors {
			d += elementDegree(e)
		}
		vinv := f.plain.inverseVandermonde(d, q)
		for k := 0; k <= d; k++ {
			w := f.productAt(t.factors, k)
			for i := 0; i <= d; i++ {
				coefForms[i].add(w, new(big.Int).Mul(t.coef, vinv[i][k]))
			}
		}
	}
	return func(j int) *linForm {
		form := newLinForm()
		if fold == nil {
			if j < len(coefForms) {
				mergeForm(form, coefForms[j], big.NewInt(1))
			}
			return form
		}
		for i, cf := range coefForms {
			if fold[i][j].Sign() != 0 {
				mergeForm(form, cf, fold[i][j])
			}
		}
		if crtForms != nil {
			mergeForm(form, crtForms[j], big.NewInt(1))
		}
		return form
	}
}

func (s *plainState) crtBasis(f *Field, q *big.Int) *crtBasis {
	if !s.crtDone {
		s.crtDone = true
		n := f.lay.NbLimbs
		fp := make(poly, n+1)
		for j, d := range s.foldDigits {
			fp[j] = new(big.Int).Neg(d)
		}
		fp[n] = big.NewInt(1)
		s.crt = newCRTBasis(polyReduce(fp, q), n, q, func(d int) [][]*big.Int { return s.inverseVandermonde(d, q) })
	}
	return s.crt
}

func (f *Field) crtProductAt(b *crtBasis, x, y *Element, k int) frontend.Variable {
	s := f.plain
	if v, ok := s.crtProducts[productKey{x, y, k}]; ok {
		return v
	}
	if v, ok := s.crtProducts[productKey{y, x, k}]; ok {
		return v
	}
	eval := func(e *Element) frontend.Variable {
		form := newLinForm()
		for i, l := range e.limbs {
			form.add(l, b.forms[k][i])
		}
		return form.build(f.api)
	}
	v := f.api.Mul(eval(x), eval(y))
	s.crtProducts[productKey{x, y, k}] = v
	return v
}

func polyMulInterval(alo, ahi, blo, bhi []*big.Int) ([]*big.Int, []*big.Int) {
	lo := make([]*big.Int, len(alo)+len(blo)-1)
	hi := make([]*big.Int, len(lo))
	for i := range lo {
		lo[i], hi[i] = new(big.Int), new(big.Int)
	}
	for i := range alo {
		for j := range blo {
			l, h := intervalMul(alo[i], ahi[i], blo[j], bhi[j])
			lo[i+j].Add(lo[i+j], l)
			hi[i+j].Add(hi[i+j], h)
		}
	}
	return lo, hi
}

func (f *Field) Lazy(in ...Term) *Element {
	if f.plain == nil || f.plain.foldDigits == nil {
		panic("lazy elements need the folded plain layout")
	}
	n, bits := f.lay.NbLimbs, f.lay.LimbBits
	halfQ := new(big.Int).Rsh(f.api.Compiler().Field(), 1)
	terms := make([]term, len(in))
	var clo, chi []*big.Int
	for i, t := range in {
		terms[i] = term{coef: big.NewInt(t.Coef), factors: t.Factors}
		lo, hi := []*big.Int{big.NewInt(t.Coef)}, []*big.Int{big.NewInt(t.Coef)}
		for _, e := range t.Factors {
			lo, hi = polyMulInterval(lo, hi, e.lo, e.hi)
		}
		clo, chi = addInto(clo, lo), addInto(chi, hi)
	}
	for i := range clo {
		if absMax(clo[i], chi[i]).Cmp(halfQ) >= 0 {
			panic("lazy coefficient does not fit the native field")
		}
	}
	degree := len(clo) - 1
	fold := f.plain.fold(n, degree)
	vForm := f.foldedForms(terms, degree, fold)
	e := &Element{limbs: make([]frontend.Variable, n), lo: make([]*big.Int, n), hi: make([]*big.Int, n), vlo: new(big.Int), vhi: new(big.Int)}
	for j := 0; j < n; j++ {
		lo, hi := new(big.Int), new(big.Int)
		for i := range clo {
			c := fold[i][j]
			switch c.Sign() {
			case 1:
				lo.Add(lo, new(big.Int).Mul(c, clo[i]))
				hi.Add(hi, new(big.Int).Mul(c, chi[i]))
			case -1:
				lo.Add(lo, new(big.Int).Mul(c, chi[i]))
				hi.Add(hi, new(big.Int).Mul(c, clo[i]))
			}
		}
		if absMax(lo, hi).Cmp(halfQ) >= 0 {
			panic("lazy limb does not fit the native field")
		}
		e.limbs[j] = vForm(j).build(f.api)
		e.lo[j], e.hi[j] = lo, hi
		e.vlo.Add(e.vlo, new(big.Int).Lsh(lo, uint(bits*j)))
		e.vhi.Add(e.vhi, new(big.Int).Lsh(hi, uint(bits*j)))
	}
	return e
}

func balanceOffset(lay Layout, widths []int) *big.Int {
	s := new(big.Int)
	for i, w := range widths {
		s.Add(s, new(big.Int).Lsh(pow2(w-1), uint(lay.LimbBits*i)))
	}
	return s
}

func (f *Field) HintBalanced(fn solver.Hint, nbOutputs int, natives []frontend.Variable, elems ...*Element) []*Element {
	api := f.api
	n := len(f.widths)
	per := f.lay.nbPiecesAll(f.widths)
	raw, err := api.Compiler().NewHint(fn, nbOutputs*per, f.hintInputs(natives, elems)...)
	if err != nil {
		panic(fmt.Sprintf("field hint: %v", err))
	}
	inputs := f.lay.header()
	for _, l := range f.modLim {
		inputs = append(inputs, l)
	}
	pieces, err := api.Compiler().NewHint(BalanceHint, nbOutputs*per, append(inputs, raw...)...)
	if err != nil {
		panic(fmt.Sprintf("balance hint: %v", err))
	}
	out := make([]*Element, nbOutputs)
	for i := range out {
		limbs := make([]frontend.Variable, n)
		lo, hi := make([]*big.Int, n), make([]*big.Int, n)
		rest := pieces[i*per : (i+1)*per]
		for j, w := range f.widths {
			k := f.lay.nbPieces(w)
			p := f.rc.Compose(rest[:k], w)
			rest = rest[k:]
			limbs[j] = api.Sub(p, pow2(w-1))
			lo[j] = new(big.Int).Neg(pow2(w - 1))
			hi[j] = new(big.Int).Sub(pow2(w-1), big.NewInt(1))
		}
		out[i] = f.WithBounds(limbs, lo, hi)
	}
	return out
}

func BalanceHint(_ *big.Int, inputs, outputs []*big.Int) error {
	lay, err := layoutOf(inputs)
	if err != nil {
		return err
	}
	n := lay.NbLimbs
	if len(inputs) < headerLen+n {
		return errors.New("balance: missing modulus")
	}
	mod := lay.recompose(inputs[headerLen : headerLen+n])
	raw := inputs[headerLen+n:]
	widths := lay.reducedWidths(mod.BitLen())
	per := lay.nbPiecesAll(widths)
	if len(raw) != len(outputs) || len(raw)%per != 0 {
		return errors.New("balance: output count mismatch")
	}
	offset := balanceOffset(lay, widths)
	for i := 0; i < len(raw); i += per {
		v := lay.recomposePieces(raw[i:i+per], widths)
		v.Add(v, offset).Mod(v, mod)
		lay.writePieces(outputs[i:i+per], v, widths)
	}
	return nil
}

func floorDiv(a, b *big.Int) *big.Int {
	return new(big.Int).Div(a, b)
}

func PlainCheckHint(q *big.Int, inputs, outputs []*big.Int) error {
	pos := 0
	next := func() *big.Int {
		v := inputs[pos]
		pos++
		return v
	}
	nextInt := func() int { return int(next().Int64()) }
	lay, err := layoutOf(inputs)
	if err != nil {
		return err
	}
	pos = headerLen
	n := lay.NbLimbs
	modLimbs := make([]*big.Int, n)
	for i := range modLimbs {
		modLimbs[i] = next()
	}
	mod := lay.recompose(modLimbs)
	hasR, hasK, kBits := nextInt(), nextInt(), nextInt()
	var kWidths []int
	if hasK == 1 {
		kWidths = lay.splitWidths(kBits)
	}
	offsetLimbs := make([]*big.Int, 0)
	if hasK == 1 {
		for range kWidths {
			offsetLimbs = append(offsetLimbs, next())
		}
	} else {
		next()
	}
	nbTerms := nextInt()
	type hterm struct {
		coef    *big.Int
		factors []int
	}
	terms := make([]hterm, nbTerms)
	for i := range terms {
		terms[i].coef = signed(next(), q)
		nf := nextInt()
		for j := 0; j < nf; j++ {
			terms[i].factors = append(terms[i].factors, nextInt())
		}
	}
	nbElems := nextInt()
	vals := make([]*big.Int, nbElems)
	for i := range vals {
		nl := nextInt()
		limbs := make([]*big.Int, nl)
		for j := range limbs {
			limbs[j] = signed(next(), q)
		}
		vals[i] = lay.recompose(limbs)
	}
	if pos != len(inputs) {
		return errors.New("inputs not exhausted")
	}
	e := new(big.Int)
	for _, t := range terms {
		v := new(big.Int).Set(t.coef)
		for _, idx := range t.factors {
			v.Mul(v, vals[idx])
		}
		e.Add(e, v)
	}
	r := new(big.Int)
	if hasR == 1 {
		r.Mod(e, mod)
	}
	out := outputs
	if hasR == 1 {
		out = lay.writePieces(out, r, lay.reducedWidths(mod.BitLen()))
	}
	if hasK == 1 {
		k := new(big.Int).Sub(e, r)
		k.Div(k, mod)
		offset := new(big.Int)
		shift := 0
		for i, o := range offsetLimbs {
			offset.Add(offset, new(big.Int).Lsh(o, uint(shift)))
			shift += kWidths[i]
		}
		kp := new(big.Int).Add(k, offset)
		if kp.Sign() < 0 || kp.BitLen() > kBits {
			kp.SetInt64(0)
		}
		out = lay.writePieces(out, kp, kWidths)
	}
	if len(out) != 0 {
		return errors.New("output count mismatch")
	}
	return nil
}
