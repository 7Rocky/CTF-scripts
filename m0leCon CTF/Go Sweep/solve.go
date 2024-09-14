package main

import (
	"fmt"
	"io"
	"sync"

	"encoding/json"
	"math/rand"
	"net/http"
)

type Cell struct {
	Revealed bool `json:"revealed"`
	Bomb     bool `json:"bomb"`
	Adjacent int  `json:"adjacent"`
	Flagged  bool `json:"flagged"`
}

type Board struct {
	Cols   int    `json:"cols"`
	Rows   int    `json:"rows"`
	GameId string `json:"gameID"`
	Seed   int64  `json:"seed"`
}

type RevealedCell struct {
	Cell Cell `json:"cell"`
	Col  int  `json:"col"`
	Row  int  `json:"row"`
}

type RevealCells struct {
	RevealedCells []RevealedCell `json:"revealedCells"`
	Status        string         `json:"status"`
	Message       string         `json:"message"`
}

const THREADS = 100

var guard = make(chan struct{}, THREADS)
var wg sync.WaitGroup

func initBoard(seed int64, size, mines int) [][]Cell {
	r := rand.New(rand.NewSource(seed))
	board := make([][]Cell, size)
	numMines := 0

	for i := range size {
		board[i] = make([]Cell, size)
	}

	for numMines < mines {
		a := r.Intn(size)
		b := r.Intn(size)

		if !board[a][b].Bomb {
			board[a][b].Bomb = true

			for k := -1; k <= 1; k++ {
				for m := -1; m <= 1; m++ {
					if k+a < size && m+b < size && k+a >= 0 && m+b >= 0 {
						board[k+a][m+b].Adjacent++
					}
				}
			}

			numMines++
		}
	}

	return board
}

func reveal(gameId string, c, r int) *RevealCells {
	guard <- struct{}{}

	res, err := http.PostForm(fmt.Sprintf("%s/reveal?gameID=%s&col=%d&row=%d", URL, gameId, c, r), nil)

	if err != nil {
		panic(err)
	}

	body, err := io.ReadAll(res.Body)

	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	var data *RevealCells

	if err := json.Unmarshal(body, &data); err != nil {
		panic(err)
	}

	<-guard
	return data
}

func solve(url string, size, mines int) {
	res, err := http.Get(url)

	if err != nil {
		panic(err)
	}

	body, err := io.ReadAll(res.Body)

	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	var data *Board

	if err := json.Unmarshal(body, &data); err != nil {
		panic(err)
	}

	board := initBoard(data.Seed, size, mines)

	for r := range size {
		for c := range size {
			go func() {
				wg.Add(1)
				defer wg.Done()

				if !board[r][c].Bomb {
					data := reveal(data.GameId, c, r)

					if data.Message != "" {
						fmt.Println(data.Message)
					}
				}
			}()
		}
	}

	wg.Wait()
}

const URL = "https://gosweep.challs.m0lecon.it"

func main() {
	solve(fmt.Sprintf("%s/new", URL), 20, 150)
	solve(fmt.Sprintf("%s/48f99e62219f9bfd9fd437b75e0d46f9", URL), 50, 2000)
}
