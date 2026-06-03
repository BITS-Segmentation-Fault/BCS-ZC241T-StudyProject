package utils

import (
	"reflect"
	"testing"
)

func TestSelectLinesWithPrefix(t *testing.T) {
	inputData := "Uid:\t1000\nGid:\t1000\nOther:\tData\nCapEff:\t00000"
	prefixes := []string{"Uid:", "CapEff:"}

	want := []string{"Uid:\t1000", "CapEff:\t00000"}
	got := SelectLinesWithPrefix(inputData, prefixes)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("SelectLinesWithPrefix got %v, want %v", got, want)
	}
}
