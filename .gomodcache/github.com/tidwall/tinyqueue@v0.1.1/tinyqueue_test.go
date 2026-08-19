package tinyqueue

import (
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"
)

type floatValue float64

func assertEqual(t *testing.T, a, b interface{}) {
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("'%v' != '%v'", a, b)
	}
}

func (a floatValue) Less(b Item) bool {
	return a < b.(floatValue)
}

var data, sorted = func() ([]Item, []Item) {
	rand.Seed(time.Now().UnixNano())
	var data []Item
	for i := 0; i < 100; i++ {
		data = append(data, floatValue(rand.Float64()*100))
	}
	sorted := make([]Item, len(data))
	copy(sorted, data)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Less(sorted[j])
	})
	return data, sorted
}()

func TestMaintainsPriorityQueue(t *testing.T) {
	q := New(nil)
	for i := 0; i < len(data); i++ {
		q.Push(data[i])
	}
	assertEqual(t, q.Peek(), sorted[0])
	var result []Item
	for q.length > 0 {
		result = append(result, q.Pop())
	}
	assertEqual(t, result, sorted)
}

func TestAcceptsDataInConstructor(t *testing.T) {
	q := New(data)
	var result []Item
	for q.length > 0 {
		result = append(result, q.Pop())
	}
	assertEqual(t, result, sorted)
}
func TestHandlesEdgeCasesWithFewElements(t *testing.T) {
	q := New(nil)
	q.Push(floatValue(2))
	q.Push(floatValue(1))
	q.Pop()
	q.Pop()
	q.Pop()
	q.Push(floatValue(2))
	q.Push(floatValue(1))
	assertEqual(t, float64(q.Pop().(floatValue)), 1.0)
	assertEqual(t, float64(q.Pop().(floatValue)), 2.0)
	assertEqual(t, q.Pop(), nil)
}
