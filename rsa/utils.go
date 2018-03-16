package rsa

import "math"

func sliceLongData(data []byte, sizeOfSlice int) [][]byte {
	var arrayBytes [][]byte
	var numberOfSlice = int(math.Ceil(float64(len(data)) / float64(sizeOfSlice)))

	for cpt := 0; cpt < numberOfSlice; cpt++ {
		arrayBytes = append(arrayBytes, data[(sizeOfSlice*cpt):int(min((sizeOfSlice*(cpt+1)), len(data)))])
	}
	return arrayBytes
}

func min(x, y int) int {
    if x < y {
        return x
    }
    return y
}
