package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	ncmWebDomain = "https://music.163.com"
	ncmAPIDomain = "https://interface3.music.163.com"
	ncmUAWeb     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
	ncmUAAPI     = "NeteaseMusic 9.0.90/5038 (iPhone; iOS 16.2; zh_CN)"
)

// neteaseClient wraps the NetEase weapi and eapi endpoints with persistent cookies
type neteaseClient struct {
	cookies  map[string]string
	deviceID string
	uid      int64
	http     *http.Client
}

// artistRef pairs an artist id with its display name
type artistRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// songItem holds track metadata returned by search and detail endpoints
type songItem struct {
	ID         int64       `json:"id"`
	Name       string      `json:"name"`
	Artists    string      `json:"artists"`
	Album      string      `json:"album"`
	CoverURL   string      `json:"coverUrl"`
	Duration   int64       `json:"duration"`
	ArtistID   int64       `json:"artistId"`
	AlbumID    int64       `json:"albumId"`
	ArtistRefs []artistRef `json:"artistRefs"`
	Ok         *bool       `json:"ok,omitempty"`
}

// albumItem holds album metadata returned by search and detail endpoints
type albumItem struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Artist      string `json:"artist"`
	CoverURL    string `json:"coverUrl"`
	TrackNum    int    `json:"trackNum"`
	PublishTime int64  `json:"publishTime"`
}

// newNeteaseClient loads persisted cookies or prepares an anonymous session
func newNeteaseClient() *neteaseClient {
	c := &neteaseClient{
		cookies: make(map[string]string),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
	c.load()
	if c.deviceID == "" {
		c.deviceID = randomHex(32)
	}
	if _, ok := c.cookies["_ntes_nuid"]; !ok {
		c.cookies["_ntes_nuid"] = randomHex(32)
	}
	return c
}

// cookieFilePath returns the path of the persisted cookie file
func cookieFilePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ncm_cookie.json"), nil
}

// load restores cookies and the device id from disk
func (c *neteaseClient) load() {
	path, err := cookieFilePath()
	if err != nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var saved struct {
		DeviceID string            `json:"deviceId"`
		Cookies  map[string]string `json:"cookies"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		return
	}
	c.deviceID = saved.DeviceID
	if saved.Cookies != nil {
		c.cookies = saved.Cookies
	}
}

// Save persists cookies and the device id to disk
func (c *neteaseClient) Save() error {
	path, err := cookieFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(map[string]any{
		"deviceId": c.deviceID,
		"cookies":  c.cookies,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// CookieFilePath returns the location of the persisted cookie file
func (c *neteaseClient) CookieFilePath() string {
	path, err := cookieFilePath()
	if err != nil {
		return ""
	}
	return path
}

// LoggedIn reports whether a login cookie is present
func (c *neteaseClient) LoggedIn() bool {
	return c.cookies["MUSIC_U"] != ""
}

// playlistItem holds metadata for one playlist of the logged in user
type playlistItem struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CoverURL   string `json:"coverUrl"`
	TrackCount int    `json:"trackCount"`
	PlayCount  int64  `json:"playCount"`
}

// Account validates the current cookies and returns the account nickname
func (c *neteaseClient) Account() (string, error) {
	body, err := c.post("/api/nuser/account/get", map[string]any{}, false)
	if err != nil {
		return "", err
	}
	profile, _ := body["profile"].(map[string]any)
	if profile == nil {
		return "", fmt.Errorf("not logged in")
	}
	c.uid = int64FromAny(profile["userId"])
	nickname, _ := profile["nickname"].(string)
	return nickname, nil
}

// Logout clears the login cookies while keeping the anonymous device identity
func (c *neteaseClient) Logout() error {
	delete(c.cookies, "MUSIC_U")
	delete(c.cookies, "MUSIC_A")
	delete(c.cookies, "MUSIC_A_T")
	delete(c.cookies, "MUSIC_R_T")
	delete(c.cookies, "MUSIC_R_U")
	delete(c.cookies, "MUSIC_SNS")
	delete(c.cookies, "__csrf")
	c.uid = 0
	return c.Save()
}

// UserPlaylists returns the playlists of the logged in account
func (c *neteaseClient) UserPlaylists() ([]playlistItem, error) {
	if c.uid == 0 {
		if _, err := c.Account(); err != nil {
			return nil, err
		}
	}
	body, err := c.post("/api/user/playlist", map[string]any{
		"uid":    c.uid,
		"limit":  100,
		"offset": 0,
	}, false)
	if err != nil {
		return nil, err
	}
	raw, _ := body["playlist"].([]any)
	out := make([]playlistItem, 0, len(raw))
	for _, entry := range raw {
		obj, _ := entry.(map[string]any)
		if obj == nil {
			continue
		}
		item := playlistItem{}
		item.ID = int64FromAny(obj["id"])
		item.Name, _ = obj["name"].(string)
		item.CoverURL, _ = obj["coverImgUrl"].(string)
		item.TrackCount = int(int64FromAny(obj["trackCount"]))
		item.PlayCount = int64FromAny(obj["playCount"])
		out = append(out, item)
	}
	return out, nil
}

// PlaylistDetail returns playlist metadata and its ordered track id list
func (c *neteaseClient) PlaylistDetail(id int64) (*playlistItem, []int64, error) {
	body, err := c.post("/api/v6/playlist/detail", map[string]any{"id": id, "n": 1000000}, false)
	if err != nil {
		return nil, nil, err
	}
	obj, _ := body["playlist"].(map[string]any)
	if obj == nil {
		return nil, nil, fmt.Errorf("playlist %d not found", id)
	}
	item := &playlistItem{}
	item.ID = int64FromAny(obj["id"])
	item.Name, _ = obj["name"].(string)
	item.CoverURL, _ = obj["coverImgUrl"].(string)
	item.TrackCount = int(int64FromAny(obj["trackCount"]))
	rawIDs, _ := obj["trackIds"].([]any)
	ids := make([]int64, 0, len(rawIDs))
	for _, entry := range rawIDs {
		if m, ok := entry.(map[string]any); ok {
			ids = append(ids, int64FromAny(m["id"]))
		}
	}
	return item, ids, nil
}

// LoginQRKey requests a new QR login key from the server
func (c *neteaseClient) LoginQRKey() (string, error) {
	body, err := c.post("/api/login/qrcode/unikey", map[string]any{"type": 1}, false)
	if err != nil {
		return "", err
	}
	key, _ := body["unikey"].(string)
	if key == "" {
		return "", fmt.Errorf("empty qr key")
	}
	return key, nil
}

// LoginQRURL returns the URL encoded inside the login QR code
func (c *neteaseClient) LoginQRURL(key string) string {
	return "https://music.163.com/login?codekey=" + url.QueryEscape(key)
}

// LoginQRCheck polls the QR login status and returns the status code
func (c *neteaseClient) LoginQRCheck(key string) (int, error) {
	body, err := c.post("/api/login/qrcode/client/login", map[string]any{"type": 1, "key": key}, false)
	if err != nil {
		return 0, err
	}
	code, _ := body["code"].(float64)
	return int(code), nil
}

// SearchSongs searches tracks by keyword
func (c *neteaseClient) SearchSongs(keyword string, limit, offset int) ([]songItem, int, error) {
	body, err := c.post("/api/cloudsearch/pc", map[string]any{
		"s":      keyword,
		"type":   1,
		"limit":  limit,
		"offset": offset,
		"total":  true,
	}, false)
	if err != nil {
		return nil, 0, err
	}
	result, _ := body["result"].(map[string]any)
	if result == nil {
		return nil, 0, nil
	}
	raw, _ := result["songs"].([]any)
	total, _ := result["songCount"].(float64)
	songs := make([]songItem, 0, len(raw))
	for _, entry := range raw {
		item := parseSongEntry(entry)
		if item != nil {
			songs = append(songs, *item)
		}
	}
	return songs, int(total), nil
}

// SearchAlbums searches albums by keyword
func (c *neteaseClient) SearchAlbums(keyword string, limit, offset int) ([]albumItem, int, error) {
	body, err := c.post("/api/cloudsearch/pc", map[string]any{
		"s":      keyword,
		"type":   10,
		"limit":  limit,
		"offset": offset,
		"total":  true,
	}, false)
	if err != nil {
		return nil, 0, err
	}
	result, _ := body["result"].(map[string]any)
	if result == nil {
		return nil, 0, nil
	}
	raw, _ := result["albums"].([]any)
	total, _ := result["albumCount"].(float64)
	albums := make([]albumItem, 0, len(raw))
	for _, entry := range raw {
		obj, _ := entry.(map[string]any)
		if obj == nil {
			continue
		}
		item := albumItem{}
		item.ID = int64FromAny(obj["id"])
		item.Name, _ = obj["name"].(string)
		item.TrackNum = int(int64FromAny(obj["size"]))
		if artist, ok := obj["artist"].(map[string]any); ok {
			item.Artist, _ = artist["name"].(string)
		}
		item.CoverURL, _ = obj["picUrl"].(string)
		albums = append(albums, item)
	}
	return albums, int(total), nil
}

// artistItem holds artist metadata returned by artist search
type artistItem struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	CoverURL  string `json:"coverUrl"`
	AlbumSize int    `json:"albumSize"`
}

// SearchSuggest returns raw keyword and entity suggestions for the given input
func (c *neteaseClient) SearchSuggest(keyword string) (map[string]any, error) {
	body, err := c.post("/api/search/suggest/web", map[string]any{"s": keyword}, false)
	if err != nil {
		return nil, err
	}
	result, _ := body["result"].(map[string]any)
	return result, nil
}

// SearchHot returns the current hot search keywords
func (c *neteaseClient) SearchHot() ([]string, error) {
	body, err := c.post("/api/search/hot", map[string]any{"type": "1111"}, false)
	if err != nil {
		return nil, err
	}
	result, _ := body["result"].(map[string]any)
	raw, _ := result["hots"].([]any)
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		if m, ok := entry.(map[string]any); ok {
			if first, ok := m["first"].(string); ok && first != "" {
				out = append(out, first)
			}
		}
	}
	return out, nil
}

// SearchArtists searches artists by keyword
func (c *neteaseClient) SearchArtists(keyword string, limit, offset int) ([]artistItem, int, error) {
	body, err := c.post("/api/cloudsearch/pc", map[string]any{
		"s":      keyword,
		"type":   100,
		"limit":  limit,
		"offset": offset,
		"total":  true,
	}, false)
	if err != nil {
		return nil, 0, err
	}
	result, _ := body["result"].(map[string]any)
	if result == nil {
		return nil, 0, nil
	}
	raw, _ := result["artists"].([]any)
	total, _ := result["artistCount"].(float64)
	artists := make([]artistItem, 0, len(raw))
	for _, entry := range raw {
		obj, _ := entry.(map[string]any)
		if obj == nil {
			continue
		}
		item := artistItem{}
		item.ID = int64FromAny(obj["id"])
		item.Name, _ = obj["name"].(string)
		item.CoverURL, _ = obj["picUrl"].(string)
		item.AlbumSize = int(int64FromAny(obj["albumSize"]))
		artists = append(artists, item)
	}
	return artists, int(total), nil
}

// ArtistAlbums fetches an artist's album list sorted from newest to oldest
func (c *neteaseClient) ArtistAlbums(id int64) ([]albumItem, error) {
	body, err := c.post(fmt.Sprintf("/api/artist/albums/%d", id), map[string]any{
		"limit":  200,
		"offset": 0,
		"total":  true,
	}, false)
	if err != nil {
		return nil, err
	}
	raw, _ := body["hotAlbums"].([]any)
	albums := make([]albumItem, 0, len(raw))
	for _, entry := range raw {
		obj, _ := entry.(map[string]any)
		if obj == nil {
			continue
		}
		item := albumItem{}
		item.ID = int64FromAny(obj["id"])
		item.Name, _ = obj["name"].(string)
		item.TrackNum = int(int64FromAny(obj["size"]))
		if artist, ok := obj["artist"].(map[string]any); ok {
			item.Artist, _ = artist["name"].(string)
		}
		item.CoverURL, _ = obj["picUrl"].(string)
		item.PublishTime = int64FromAny(obj["publishTime"])
		albums = append(albums, item)
	}
	sort.Slice(albums, func(i, j int) bool { return albums[i].PublishTime > albums[j].PublishTime })
	return albums, nil
}

// SongDetail fetches full metadata for one track
func (c *neteaseClient) SongDetail(id int64) (*songItem, error) {
	body, err := c.post("/api/v3/song/detail", map[string]any{
		"c": fmt.Sprintf(`[{"id":%d}]`, id),
	}, false)
	if err != nil {
		return nil, err
	}
	raw, _ := body["songs"].([]any)
	if len(raw) == 0 {
		return nil, fmt.Errorf("song %d not found", id)
	}
	item := parseSongEntry(raw[0])
	if item == nil {
		return nil, fmt.Errorf("song %d not found", id)
	}
	return item, nil
}

// songQuality holds the quality levels a song actually offers to the current account
type songQuality struct {
	Levels []string
	Top    string
	Type   string
}

// qualityLevels lists the quality levels from lowest to highest
var qualityLevels = []string{"standard", "higher", "exhigh", "lossless", "hires", "jyeffect", "sky", "dolby", "jymaster"}

// levelSource maps the classic quality levels to their song detail quality object keys
var levelSource = map[string]string{
	"standard": "l",
	"higher":   "m",
	"exhigh":   "h",
	"lossless": "sq",
	"hires":    "hr",
}

// levelIndex returns the ladder position of a quality level or -1 when unknown
func levelIndex(level string) int {
	for i, l := range qualityLevels {
		if l == level {
			return i
		}
	}
	return -1
}

// songQualityFrom derives the available quality levels from a detail entry and its privilege
func songQualityFrom(song, privilege map[string]any) songQuality {
	out := songQuality{}
	st := int64FromAny(privilege["st"])
	dl := int64FromAny(privilege["dl"])
	dlLevel, _ := privilege["dlLevel"].(string)
	maxLevel, _ := privilege["maxBrLevel"].(string)
	if st < 0 || dl <= 0 || dlLevel == "" || dlLevel == "none" {
		return out
	}
	capIdx := levelIndex(dlLevel)
	if capIdx < 0 {
		capIdx = levelIndex(maxLevel)
	}
	maxIdx := levelIndex(maxLevel)
	if maxIdx < 0 {
		maxIdx = capIdx
	}
	for i, lv := range qualityLevels {
		if capIdx < 0 || i > capIdx {
			break
		}
		if key, ok := levelSource[lv]; ok {
			v, exists := song[key]
			if !exists || v == nil {
				continue
			}
		} else if i > maxIdx {
			continue
		}
		out.Levels = append(out.Levels, lv)
	}
	if len(out.Levels) == 0 {
		return out
	}
	out.Top = out.Levels[len(out.Levels)-1]
	out.Type = "mp3"
	if levelIndex(out.Top) >= levelIndex("lossless") {
		out.Type = "flac"
	}
	return out
}

// SongQualities fetches the available quality levels for the given songs
func (c *neteaseClient) SongQualities(ids []int64) (map[int64]songQuality, error) {
	_, qualities, err := c.songsDetail(ids)
	return qualities, err
}

// SongsMeta fetches metadata for the given song ids
func (c *neteaseClient) SongsMeta(ids []int64) (map[int64]songItem, error) {
	items, _, err := c.songsDetail(ids)
	return items, err
}

// songsDetail fetches song metadata and quality info in batches of 200
func (c *neteaseClient) songsDetail(ids []int64) (map[int64]songItem, map[int64]songQuality, error) {
	items := make(map[int64]songItem, len(ids))
	qualities := make(map[int64]songQuality, len(ids))
	for start := 0; start < len(ids); start += 200 {
		if start > 0 {
			time.Sleep(400 * time.Millisecond)
		}
		end := min(start+200, len(ids))
		parts := make([]string, 0, end-start)
		for _, id := range ids[start:end] {
			parts = append(parts, fmt.Sprintf(`{"id":%d}`, id))
		}
		body, err := c.post("/api/v3/song/detail", map[string]any{"c": "[" + strings.Join(parts, ",") + "]"}, false)
		if err != nil {
			return nil, nil, err
		}
		privByID := make(map[int64]map[string]any)
		rawPriv, _ := body["privileges"].([]any)
		for _, entry := range rawPriv {
			obj, _ := entry.(map[string]any)
			if obj == nil {
				continue
			}
			privByID[int64FromAny(obj["id"])] = obj
		}
		rawSongs, _ := body["songs"].([]any)
		for _, entry := range rawSongs {
			obj, _ := entry.(map[string]any)
			if obj == nil {
				continue
			}
			id := int64FromAny(obj["id"])
			if item := parseSongEntry(obj); item != nil {
				items[id] = *item
			}
			qualities[id] = songQualityFrom(obj, privByID[id])
		}
	}
	return items, qualities, nil
}

// AlbumDetail fetches album metadata and its track list
func (c *neteaseClient) AlbumDetail(id int64) (*albumItem, []songItem, error) {
	body, err := c.post(fmt.Sprintf("/api/v1/album/%d", id), map[string]any{}, false)
	if err != nil {
		return nil, nil, err
	}
	albumObj, _ := body["album"].(map[string]any)
	if albumObj == nil {
		return nil, nil, fmt.Errorf("album %d not found", id)
	}
	album := &albumItem{}
	album.ID = int64FromAny(albumObj["id"])
	album.Name, _ = albumObj["name"].(string)
	album.CoverURL, _ = albumObj["picUrl"].(string)
	album.TrackNum = int(int64FromAny(albumObj["size"]))
	if artist, ok := albumObj["artist"].(map[string]any); ok {
		album.Artist, _ = artist["name"].(string)
	}
	raw, _ := body["songs"].([]any)
	songs := make([]songItem, 0, len(raw))
	for _, entry := range raw {
		item := parseSongEntry(entry)
		if item != nil {
			songs = append(songs, *item)
		}
	}
	return album, songs, nil
}

// songURLInfo describes the downloadable stream for one track
type songURLInfo struct {
	URL   string
	Level string
	Type  string
	Size  int64
}

// SongURL requests a playable download URL at the given quality level
func (c *neteaseClient) SongURL(id int64, level string) (*songURLInfo, error) {
	body, err := c.post("/api/song/enhance/player/url/v1", map[string]any{
		"ids":        fmt.Sprintf("[%d]", id),
		"level":      level,
		"encodeType": "flac",
	}, false)
	if err != nil {
		return nil, err
	}
	raw, _ := body["data"].([]any)
	if len(raw) == 0 {
		return nil, fmt.Errorf("no url data for song %d", id)
	}
	entry, _ := raw[0].(map[string]any)
	if entry == nil {
		return nil, fmt.Errorf("no url data for song %d", id)
	}
	songURL, _ := entry["url"].(string)
	if songURL == "" || songURL == "null" {
		levelName, _ := entry["level"].(string)
		if levelName == "" {
			levelName = level
		}
		return nil, fmt.Errorf("song %d has no downloadable url at level %s", id, levelName)
	}
	info := &songURLInfo{}
	info.URL = songURL
	info.Level, _ = entry["level"].(string)
	info.Type, _ = entry["type"].(string)
	info.Size = int64FromAny(entry["size"])
	if info.Type == "" {
		info.Type = "mp3"
	}
	return info, nil
}

// parseSongEntry converts one raw search or detail entry into a songItem
func parseSongEntry(entry any) *songItem {
	obj, _ := entry.(map[string]any)
	if obj == nil {
		return nil
	}
	item := &songItem{}
	item.ID = int64FromAny(obj["id"])
	item.Name, _ = obj["name"].(string)
	item.Duration = int64FromAny(obj["dt"])
	if item.Duration == 0 {
		item.Duration = int64FromAny(obj["duration"])
	}
	var names []string
	var refs []artistRef
	if ar, ok := obj["ar"].([]any); ok {
		for _, a := range ar {
			if m, ok := a.(map[string]any); ok {
				n, _ := m["name"].(string)
				names = append(names, n)
				refs = append(refs, artistRef{ID: int64FromAny(m["id"]), Name: n})
			}
		}
	} else if ar, ok := obj["artists"].([]any); ok {
		for _, a := range ar {
			if m, ok := a.(map[string]any); ok {
				n, _ := m["name"].(string)
				names = append(names, n)
				refs = append(refs, artistRef{ID: int64FromAny(m["id"]), Name: n})
			}
		}
	}
	item.Artists = strings.Join(names, ",")
	item.ArtistRefs = refs
	if len(refs) > 0 {
		item.ArtistID = refs[0].ID
	}
	if al, ok := obj["al"].(map[string]any); ok {
		item.Album, _ = al["name"].(string)
		item.CoverURL, _ = al["picUrl"].(string)
		item.AlbumID = int64FromAny(al["id"])
	} else if al, ok := obj["album"].(map[string]any); ok {
		item.Album, _ = al["name"].(string)
		item.CoverURL, _ = al["picUrl"].(string)
		item.AlbumID = int64FromAny(al["id"])
	}
	return item
}

// int64FromAny converts a JSON number value into int64
func int64FromAny(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		var out int64
		fmt.Sscanf(n, "%d", &out)
		return out
	}
	return 0
}

// randomHex returns a random hex string of n characters
func randomHex(n int) string {
	buf := make([]byte, n/2)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

// post sends an encrypted request and returns the decoded JSON object
func (c *neteaseClient) post(uri string, data map[string]any, eapiMode bool) (map[string]any, error) {
	cookie := c.requestCookies(uri)
	form := url.Values{}
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	if eapiMode {
		header := c.eapiHeader(cookie)
		data["header"] = header
		dataJSON, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		params, err := eapiEncrypt(uri, string(dataJSON))
		if err != nil {
			return nil, err
		}
		form.Set("params", params)
		headers["User-Agent"] = ncmUAAPI
		headers["Cookie"] = headerCookieString(header)
		return c.send(ncmAPIDomain+"/eapi/"+strings.TrimPrefix(uri, "/api/"), form, headers)
	}
	data["csrf_token"] = cookie["__csrf"]
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	params, encSecKey, err := weapiEncrypt(string(dataJSON))
	if err != nil {
		return nil, err
	}
	form.Set("params", params)
	form.Set("encSecKey", encSecKey)
	headers["User-Agent"] = ncmUAWeb
	headers["Referer"] = ncmWebDomain
	headers["Cookie"] = cookieString(cookie)
	return c.send(ncmWebDomain+"/weapi/"+strings.TrimPrefix(uri, "/api/"), form, headers)
}

// send performs the HTTP POST and merges any Set-Cookie values into the session
func (c *neteaseClient) send(endpoint string, form url.Values, headers map[string]string) (map[string]any, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader([]byte(form.Encode())))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.mergeCookies(resp.Cookies())
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if code, ok := out["code"].(float64); ok && code != 200 && code != 801 && code != 802 && code != 803 && code != 800 {
		if int(code) == 401 {
			return nil, fmt.Errorf("接口被限流或登录已失效，请稍后再试")
		}
		return nil, fmt.Errorf("api error code %v", code)
	}
	return out, nil
}

// mergeCookies stores Set-Cookie values from a response into the session
func (c *neteaseClient) mergeCookies(cookies []*http.Cookie) {
	for _, ck := range cookies {
		if ck.Name != "" {
			c.cookies[ck.Name] = ck.Value
		}
	}
}

// requestCookies builds the cookie map sent with a request
func (c *neteaseClient) requestCookies(uri string) map[string]string {
	cookie := make(map[string]string, len(c.cookies)+8)
	maps.Copy(cookie, c.cookies)
	cookie["os"] = "pc"
	cookie["osver"] = "Microsoft-Windows-10-Professional-build-19045-64bit"
	cookie["appver"] = "3.1.17.204416"
	cookie["channel"] = "netease"
	cookie["deviceId"] = c.deviceID
	cookie["__remember_me"] = "true"
	cookie["WEVNSM"] = "1.0.0"
	if cookie["_ntes_nnid"] == "" {
		cookie["_ntes_nnid"] = cookie["_ntes_nuid"] + "," + fmt.Sprintf("%d", time.Now().UnixMilli())
	}
	if !strings.Contains(uri, "login") && cookie["NMTID"] == "" {
		cookie["NMTID"] = randomHex(16)
	}
	return cookie
}

// eapiHeader builds the header object embedded into eapi request payloads
func (c *neteaseClient) eapiHeader(cookie map[string]string) map[string]string {
	header := map[string]string{
		"osver":       cookie["osver"],
		"deviceId":    c.deviceID,
		"os":          cookie["os"],
		"appver":      cookie["appver"],
		"versioncode": "140",
		"buildver":    fmt.Sprintf("%d", time.Now().Unix()),
		"resolution":  "1920x1080",
		"__csrf":      c.cookies["__csrf"],
		"channel":     "netease",
		"requestId":   fmt.Sprintf("%d_%04d", time.Now().UnixMilli(), time.Now().UnixNano()%1000),
	}
	if v := c.cookies["MUSIC_U"]; v != "" {
		header["MUSIC_U"] = v
	}
	if v := c.cookies["MUSIC_A"]; v != "" {
		header["MUSIC_A"] = v
	}
	return header
}

// cookieString joins a cookie map into a Cookie header value
func cookieString(cookie map[string]string) string {
	parts := make([]string, 0, len(cookie))
	for k, v := range cookie {
		parts = append(parts, k+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "; ")
}

// headerCookieString joins the eapi header map into a Cookie header value
func headerCookieString(header map[string]string) string {
	parts := make([]string, 0, len(header))
	for k, v := range header {
		parts = append(parts, k+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "; ")
}
