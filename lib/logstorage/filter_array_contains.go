package logstorage

import (
	"fmt"
	"strings"

	"github.com/VictoriaMetrics/VictoriaLogs/lib/prefixfilter"
	"github.com/valyala/fastjson"
)

// filterArrayContains matches if the JSON array in the given field contains the given value.
//
// Example LogsQL: `tags:array_contains("prod")`
type filterArrayContains struct {
	fieldName string
	value     string
}

func (fa *filterArrayContains) String() string {
	return fmt.Sprintf("%sarray_contains(%s)", quoteFieldNameIfNeeded(fa.fieldName), quoteTokenIfNeeded(fa.value))
}

func (fa *filterArrayContains) updateNeededFields(pf *prefixfilter.Filter) {
	pf.AddAllowFilter(fa.fieldName)
}

func (fa *filterArrayContains) matchRow(fields []Field) bool {
	v := getFieldValueByName(fields, fa.fieldName)
	return matchArrayContains(v, fa.value)
}

func (fa *filterArrayContains) applyToBlockResult(br *blockResult, bm *bitmap) {
	c := br.getColumnByName(fa.fieldName)
	if c.isConst {
		v := c.valuesEncoded[0]
		if !matchArrayContains(v, fa.value) {
			bm.resetBits()
		}
		return
	}
	if c.isTime {
		bm.resetBits()
		return
	}

	switch c.valueType {
	case valueTypeString:
		values := c.getValues(br)
		bm.forEachSetBit(func(idx int) bool {
			v := values[idx]
			return matchArrayContains(v, fa.value)
		})
	case valueTypeDict:
		bb := bbPool.Get()
		for _, v := range c.dictValues {
			c := byte(0)
			if matchArrayContains(v, fa.value) {
				c = 1
			}
			bb.B = append(bb.B, c)
		}
		valuesEncoded := c.getValuesEncoded(br)
		bm.forEachSetBit(func(idx int) bool {
			n := valuesEncoded[idx][0]
			return bb.B[n] == 1
		})
		bbPool.Put(bb)
	default:
		bm.resetBits()
	}
}

func (fa *filterArrayContains) applyToBlockSearch(bs *blockSearch, bm *bitmap) {
	fieldName := fa.fieldName
	value := fa.value

	v := bs.getConstColumnValue(fieldName)
	if v != "" {
		if !matchArrayContains(v, value) {
			bm.resetBits()
		}
		return
	}

	// Verify whether filter matches other columns
	ch := bs.getColumnHeader(fieldName)
	if ch == nil {
		// Fast path - there are no matching columns.
		bm.resetBits()
		return
	}

	switch ch.valueType {
	case valueTypeString:
		matchStringByArrayContains(bs, ch, bm, value)
	case valueTypeDict:
		matchValuesDictByArrayContains(bs, ch, bm, value)
	default:
		bm.resetBits()
	}
}

func matchValuesDictByArrayContains(bs *blockSearch, ch *columnHeader, bm *bitmap, value string) {
	bb := bbPool.Get()
	for _, v := range ch.valuesDict.values {
		c := byte(0)
		if matchArrayContains(v, value) {
			c = 1
		}
		bb.B = append(bb.B, c)
	}
	matchEncodedValuesDict(bs, ch, bm, bb.B)
	bbPool.Put(bb)
}

func matchStringByArrayContains(bs *blockSearch, ch *columnHeader, bm *bitmap, value string) {
	visitValues(bs, ch, bm, func(v string) bool {
		return matchArrayContains(v, value)
	})
}

func matchArrayContains(s, value string) bool {
	if s == "" {
		return false
	}
	// Fast check: if the value is not present as a substring, it definitely won't be in the array.
	if !strings.Contains(s, value) {
		return false
	}

	// Fast check 2: must start with [
	if s[0] != '[' {
		return false
	}

	// Use shared fastjson.ParserPool in order to avoid per-call parser allocations.
	p := jspp.Get()
	defer jspp.Put(p)
	v, err := p.Parse(s)
	if err != nil {
		return false
	}

	// Check if it is an array
	a, err := v.Array()
	if err != nil {
		return false
	}

	for _, elem := range a {
		// We only support checking against string representation of values in the array.
		var sElem string
		switch elem.Type() {
		case fastjson.TypeString:
			sElem = string(elem.GetStringBytes())
		case fastjson.TypeNumber:
			sElem = elem.String()
		case fastjson.TypeTrue:
			sElem = "true"
		case fastjson.TypeFalse:
			sElem = "false"
		case fastjson.TypeNull:
			sElem = "null"
		default:
			continue
		}

		if sElem == value {
			return true
		}
	}

	return false
}
