package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// 分类键
const (
	PoliticalHigh   = "political_high"
	PoliticalLow    = "political_low"
	PoliticalPerson = "political_person"
	PoliticalBanned = "political_banned_books"
	PoliticalProhib = "political_prohibited"
	ViolentHigh     = "violent_high"
	ViolentLow      = "violent_low"
	ViolentChemical = "violent_chemical"
	PornHigh        = "pornographic_high"
	PornLow         = "pornographic_low"
	AbusiveHigh     = "abusive_high"
	AbusiveLow      = "abusive_low"
	AdvertisingHigh = "advertising_high"
	AdvertisingLow  = "advertising_low"
)

var CategoryDisplay = map[string]string{
	PoliticalHigh:   "政治高敏感",
	PoliticalLow:    "政治低敏感",
	PoliticalPerson: "政治敏感人物",
	PoliticalBanned: "禁书",
	PoliticalProhib: "政治违禁词",
	ViolentHigh:     "暴恐高敏感",
	ViolentLow:      "暴恐低敏感",
	ViolentChemical: "化学药剂",
	PornHigh:        "涉黄高敏感",
	PornLow:         "涉黄低敏感",
	AbusiveHigh:     "辱骂高敏感",
	AbusiveLow:      "辱骂低敏感",
	AdvertisingHigh: "广告高敏感",
	AdvertisingLow:  "广告低敏感",
}

type Detector struct {
	basePath       string
	sensitiveWords map[string]map[string]struct{} // cat -> set(word)
	automata       map[string]*ACAutomaton        // cat -> AC
	reNoSymbol     *regexp.Regexp
}

func NewDetector(basePath string) *Detector {
	d := &Detector{
		basePath:       basePath,
		sensitiveWords: make(map[string]map[string]struct{}),
		automata:       make(map[string]*ACAutomaton),
		reNoSymbol:     regexp.MustCompile(`[^\p{L}\p{N}_，。]`),
	}
	for cat := range CategoryDisplay {
		d.sensitiveWords[cat] = make(map[string]struct{})
	}
	d.loadSensitiveWords()
	d.buildAutomata()
	return d
}

// ================= 词库加载 =================

func (d *Detector) loadSensitiveWords() {
	// 目录与 Python 版本保持一致
	d.loadFiles([]string{
		"政治敏感词/政治高敏感词(不含数字不含人名).txt",
		"政治敏感词/政治高敏感词(含数字).txt",
	}, PoliticalHigh)

	d.loadFiles([]string{
		"政治敏感词/政治低敏感词(不含数字).txt",
		"政治敏感词/政治低敏感词(含数字).txt",
	}, PoliticalLow)

	d.loadFiles([]string{
		"政治敏感词/政治高敏感词(不含数字含人名).txt",
		"政治敏感词/政治低敏感词(不含数字含人名).txt",
	}, PoliticalPerson)

	d.loadFiles([]string{
		"政治敏感词/禁书.txt",
	}, PoliticalBanned)

	d.loadFiles([]string{
		"政治敏感词/违禁词/违禁词（总）.txt",
		"政治敏感词/违禁词/违禁词（含数字）.txt",
	}, PoliticalProhib)

	d.loadFiles([]string{
		"暴恐类敏感词/暴恐高敏感词(不含数字).txt",
		"暴恐类敏感词/暴恐高敏感词(含数字).txt",
	}, ViolentHigh)

	d.loadFiles([]string{
		"暴恐类敏感词/暴恐低敏感词(不含数字).txt",
		"暴恐类敏感词/暴恐低敏感词(含数字).txt",
	}, ViolentLow)

	d.loadFiles([]string{
		"暴恐类敏感词/化学药剂.txt",
	}, ViolentChemical)

	d.loadFiles([]string{
		"涉黄类敏感词/涉黄高敏感词（添加版）.txt",
	}, PornHigh)

	d.loadFiles([]string{
		"涉黄类敏感词/涉黄低敏感词（添加版）.txt",
	}, PornLow)

	d.loadFiles([]string{
		"辱骂类敏感词/辱骂高敏感词（添加版）.txt",
		"辱骂类敏感词/辱骂高敏感词（添加版）(同音替换).txt",
	}, AbusiveHigh)

	d.loadFiles([]string{
		"辱骂类敏感词/辱骂低敏感词（添加版）.txt",
	}, AbusiveLow)

	d.loadFiles([]string{
		"拉人广告敏感词/高敏感词.txt",
	}, AdvertisingHigh)

	d.loadFiles([]string{
		"拉人广告敏感词/低敏感词.txt",
	}, AdvertisingLow)
}

func (d *Detector) loadFiles(relPaths []string, category string) {
	for _, p := range relPaths {
		full := filepath.Join(d.basePath, p)
		f, err := os.Open(full)
		if err != nil {
			// 文件不存在也允许启动
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			w := strings.TrimSpace(sc.Text())
			if w == "" || strings.HasPrefix(w, "#") {
				continue
			}
			d.sensitiveWords[category][w] = struct{}{}
		}
		_ = f.Close()
	}
}

func (d *Detector) buildAutomata() {
	for cat, set := range d.sensitiveWords {
		words := make([]string, 0, len(set))
		for w := range set {
			words = append(words, w)
		}
		sort.Strings(words)
		ac := NewAC()
		ac.Build(words)
		d.automata[cat] = ac
	}
}

// ================= 检测与统计 =================

type DetectRequest struct {
	Text       string   `json:"text"`
	Categories []string `json:"categories"` // 可选；为空时使用全部分类
}

type WordHit struct {
	Word              string `json:"word"`
	CountRaw          int    `json:"count_raw"`
	CountNoSymbol     int    `json:"count_no_symbol"`
	TotalCount        int    `json:"total_count"`
	Level             string `json:"level"`          // high/low（单字降级低）
	OriginalLevel     string `json:"original_level"` // 类别原生级别
	PositionsRaw      []int  `json:"positions_raw"`  // rune 开始下标
	PositionsNoSymbol []int  `json:"positions_no_symbol"`
}

type CategoryResult struct {
	Count int            `json:"count"`
	Words []WordHit      `json:"words"`
	Stats map[string]int `json:"stats"` // {"high":x,"low":y}
}

type DetectResponse struct {
	HasSensitive     bool                      `json:"has_sensitive"`
	TotalCount       int                       `json:"total_count"`
	Categories       map[string]CategoryResult `json:"categories"`
	DetectedWords    []WordHit                 `json:"detected_words"`
	RiskLevel        string                    `json:"risk_level"` // safe/low/high
	CategorySummary  map[string]map[string]int `json:"category_summary"`
	SimilarWords     []any                     `json:"similar_words"`     // 保留字段（本实现未启用）
	SimilarSensitive bool                      `json:"similar_sensitive"` // 与 Python 版本保持字段一致
}

func (d *Detector) levelOf(category, word string) (level, original string) {
	original = "low"
	if strings.Contains(category, "high") ||
		strings.Contains(category, "banned_books") ||
		strings.Contains(category, "prohibited") ||
		strings.Contains(category, "person") {
		original = "high"
	}
	// 单字降级为 low
	if runeCount(word) == 1 {
		return "low", original
	}
	if original == "high" {
		return "high", original
	}
	return "low", original
}

func runeCount(s string) int {
	return len([]rune(s))
}

func (d *Detector) Detect(text string, categories []string) DetectResponse {
	// 类别选择
	if len(categories) == 0 {
		for cat := range d.automata {
			categories = append(categories, cat)
		}
	}
	textNoSymbol := d.reNoSymbol.ReplaceAllString(text, "")

	resp := DetectResponse{
		Categories:       map[string]CategoryResult{},
		CategorySummary:  map[string]map[string]int{},
		RiskLevel:        "safe",
		SimilarWords:     []any{},
		SimilarSensitive: true, // 与你的新版本保持一致
	}

	for _, cat := range categories {
		A := d.automata[cat]
		if A == nil {
			continue
		}
		type agg struct {
			countRaw, countNoSymbol int
			posRaw, posNoSymbol     []int
		}
		aggm := map[string]*agg{}

		// 原文
		for _, m := range A.Search(text) {
			a := aggm[m.Word]
			if a == nil {
				a = &agg{}
				aggm[m.Word] = a
			}
			a.countRaw++
			a.posRaw = append(a.posRaw, m.Start)
		}
		// 去符号
		for _, m := range A.Search(textNoSymbol) {
			a := aggm[m.Word]
			if a == nil {
				a = &agg{}
				aggm[m.Word] = a
			}
			a.countNoSymbol++
			a.posNoSymbol = append(a.posNoSymbol, m.Start)
		}

		if len(aggm) == 0 {
			continue
		}

		cr := CategoryResult{
			Stats: map[string]int{"high": 0, "low": 0},
		}

		for w, a := range aggm {
			total := a.countRaw + a.countNoSymbol
			if total == 0 {
				continue
			}
			lvl, orig := d.levelOf(cat, w)
			cr.Stats[lvl]++

			h := WordHit{
				Word:              w,
				CountRaw:          a.countRaw,
				CountNoSymbol:     a.countNoSymbol,
				TotalCount:        total,
				Level:             lvl,
				OriginalLevel:     orig,
				PositionsRaw:      a.posRaw,
				PositionsNoSymbol: a.posNoSymbol,
			}
			cr.Words = append(cr.Words, h)
			resp.DetectedWords = append(resp.DetectedWords, h)
		}
		cr.Count = len(cr.Words)
		resp.Categories[cat] = cr
		resp.TotalCount += cr.Count
	}

	// 风险等级
	if resp.TotalCount > 0 {
		highCnt := 0
		for _, w := range resp.DetectedWords {
			if w.Level == "high" {
				highCnt++
			}
		}
		if highCnt > 0 {
			resp.RiskLevel = "high"
		} else {
			resp.RiskLevel = "low"
		}
		resp.HasSensitive = true
	}

	// 分类统计摘要
	for cat, data := range resp.Categories {
		resp.CategorySummary[cat] = map[string]int{
			"total": data.Count,
			"high":  data.Stats["high"],
			"low":   data.Stats["low"],
		}
	}
	return resp
}

func (d *Detector) Statistics() map[string]int {
	stats := map[string]int{}
	total := 0

	// 大类统计
	stats["political"] = len(d.sensitiveWords[PoliticalHigh]) +
		len(d.sensitiveWords[PoliticalLow]) +
		len(d.sensitiveWords[PoliticalPerson]) +
		len(d.sensitiveWords[PoliticalBanned]) +
		len(d.sensitiveWords[PoliticalProhib])

	stats["violent"] = len(d.sensitiveWords[ViolentHigh]) +
		len(d.sensitiveWords[ViolentLow]) +
		len(d.sensitiveWords[ViolentChemical])

	stats["pornographic"] = len(d.sensitiveWords[PornHigh]) +
		len(d.sensitiveWords[PornLow])

	stats["abusive"] = len(d.sensitiveWords[AbusiveHigh]) +
		len(d.sensitiveWords[AbusiveLow])

	stats["advertising"] = len(d.sensitiveWords[AdvertisingHigh]) +
		len(d.sensitiveWords[AdvertisingLow])

	// 子类统计
	for cat, set := range d.sensitiveWords {
		c := len(set)
		stats[cat] = c
		total += c
	}
	stats["total"] = total
	return stats
}
