package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bogem/id3v2"
	"github.com/go-flac/flacpicture"
	"github.com/go-flac/go-flac"
)

// ncmMetadata holds metadata from NCM files
type ncmMetadata struct {
	MusicName string          `json:"musicName"`
	Album     string          `json:"album"`
	Artist    json.RawMessage `json:"artist"`
	Format    string          `json:"format"`
}

// AES/ECB helper functions

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{b: b, blockSize: b.BlockSize()}
}

func (x *ecb) Decrypt(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func (x *ecb) Encrypt(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func unpad(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return src
	}
	unpadding := int(src[length-1])
	if unpadding > length {
		return src
	}
	return src[:length-unpadding]
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex constant: " + s)
	}
	return b
}

func newAESCipher(key []byte) cipher.Block {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("aes.NewCipher failed: " + err.Error())
	}
	return block
}

var (
	coreKey = mustHex("687A4852416D736F356B496E62617857")
	metaKey = mustHex("2331346C6A6B5F215C5D2630553C2728")
)

// parseArtist extracts artist name from NCM metadata
func parseArtist(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return "Unknown Artist"
	}

	var nested [][]string
	if err := json.Unmarshal(raw, &nested); err == nil {
		var names []string
		for _, a := range nested {
			if len(a) > 0 {
				names = append(names, a[0])
			}
		}
		return strings.Join(names, "/")
	}

	var mixed []any
	if err := json.Unmarshal(raw, &mixed); err == nil {
		var names []string
		for _, v := range mixed {
			switch val := v.(type) {
			case string:
				names = append(names, val)
			case float64:
				names = append(names, fmt.Sprintf("%.0f", val))
			}
		}
		return strings.Join(names, "/")
	}

	var single any
	if err := json.Unmarshal(raw, &single); err == nil {
		switch val := single.(type) {
		case string:
			return val
		case float64:
			return fmt.Sprintf("%.0f", val)
		}
	}

	return "Unknown Artist"
}

// buildVorbisCommentBlock creates a Vorbis Comment metadata block
func buildVorbisCommentBlock(comments [][2]string) *flac.MetaDataBlock {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(len(comments)))
	for _, kv := range comments {
		entry := kv[0] + "=" + kv[1]
		binary.Write(&buf, binary.LittleEndian, uint32(len(entry)))
		buf.WriteString(entry)
	}
	return &flac.MetaDataBlock{
		Type: flac.VorbisComment,
		Data: buf.Bytes(),
	}
}

// embedFLAC embeds metadata and cover into a FLAC file
func embedFLAC(path string, meta *ncmMetadata, artist string, imageData []byte) error {
	f, err := flac.ParseFile(path)
	if err != nil {
		return err
	}

	f.Meta = append(f.Meta, buildVorbisCommentBlock([][2]string{
		{"TITLE", meta.MusicName},
		{"ALBUM", meta.Album},
		{"ARTIST", artist},
	}))

	if len(imageData) > 0 {
		mimeType := "image/jpeg"
		if bytes.HasPrefix(imageData, []byte{0x89, 0x50}) {
			mimeType = "image/png"
		}
		pic, err := flacpicture.NewFromImageData(
			flacpicture.PictureTypeFrontCover, "", imageData, mimeType,
		)
		if err == nil {
			picBlock := pic.Marshal()
			f.Meta = append(f.Meta, &picBlock)
		}
	}

	return f.Save(path)
}

// embedFLACCover embeds a cover image into an existing FLAC file
func embedFLACCover(path string, coverData []byte) error {
	f, err := flac.ParseFile(path)
	if err != nil {
		return err
	}

	if len(coverData) > 0 {
		mimeType := "image/jpeg"
		if bytes.HasPrefix(coverData, []byte{0x89, 0x50}) {
			mimeType = "image/png"
		}
		pic, err := flacpicture.NewFromImageData(
			flacpicture.PictureTypeFrontCover, "", coverData, mimeType,
		)
		if err == nil {
			picBlock := pic.Marshal()
			f.Meta = append(f.Meta, &picBlock)
		}
	}

	return f.Save(path)
}

// embedMP3 embeds metadata and cover into an MP3 file
func embedMP3(path string, meta *ncmMetadata, artist string, imageData []byte) error {
	tag, err := id3v2.Open(path, id3v2.Options{Parse: false})
	if err != nil {
		return err
	}
	defer tag.Close()

	tag.SetDefaultEncoding(id3v2.EncodingUTF8)
	tag.SetTitle(meta.MusicName)
	tag.SetArtist(artist)
	tag.SetAlbum(meta.Album)

	if len(imageData) > 0 {
		mimeType := "image/jpeg"
		if bytes.HasPrefix(imageData, []byte{0x89, 0x50}) {
			mimeType = "image/png"
		}
		tag.AddAttachedPicture(id3v2.PictureFrame{
			Encoding:    id3v2.EncodingUTF8,
			MimeType:    mimeType,
			PictureType: id3v2.PTFrontCover,
			Picture:     imageData,
		})
	}

	return tag.Save()
}

// convertNcmFile converts a NCM file to MP3 or FLAC format
func convertNcmFile(inputPath, outputDir string) (format string, err error) {
	file, err := os.Open(inputPath)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer file.Close()

	header := make([]byte, 8)
	if _, err := io.ReadFull(file, header); err != nil {
		return "", fmt.Errorf("read header: %w", err)
	}
	if string(header) != "CTENFDAM" {
		return "", errors.New("invalid ncm header")
	}
	if _, err := file.Seek(2, io.SeekCurrent); err != nil {
		return "", fmt.Errorf("seek: %w", err)
	}

	var keyLength uint32
	if err := binary.Read(file, binary.LittleEndian, &keyLength); err != nil {
		return "", fmt.Errorf("read key length: %w", err)
	}
	keyDataEnc := make([]byte, keyLength)
	if _, err := io.ReadFull(file, keyDataEnc); err != nil {
		return "", fmt.Errorf("read key data: %w", err)
	}
	for i := range keyDataEnc {
		keyDataEnc[i] ^= 0x64
	}
	block := newAESCipher(coreKey)
	ecbDec := newECB(block)
	keyDataPadded := make([]byte, len(keyDataEnc))
	ecbDec.Decrypt(keyDataPadded, keyDataEnc)
	keyData := unpad(keyDataPadded)[17:]

	keyBox := make([]byte, 256)
	for i := range keyBox {
		keyBox[i] = byte(i)
	}
	c, lastByte, keyOffset := byte(0), byte(0), 0
	for i := range 256 {
		c = keyBox[i] + lastByte + keyData[keyOffset]
		keyOffset = (keyOffset + 1) % len(keyData)
		keyBox[i], keyBox[c] = keyBox[c], keyBox[i]
		lastByte = c
	}

	var metaLength uint32
	if err := binary.Read(file, binary.LittleEndian, &metaLength); err != nil {
		return "", fmt.Errorf("read meta length: %w", err)
	}
	metaDataEnc := make([]byte, metaLength)
	if _, err := io.ReadFull(file, metaDataEnc); err != nil {
		return "", fmt.Errorf("read meta data: %w", err)
	}
	for i := range metaDataEnc {
		metaDataEnc[i] ^= 0x63
	}
	metaDataB64, err := base64.StdEncoding.DecodeString(string(metaDataEnc[22:]))
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	block = newAESCipher(metaKey)
	ecbDec = newECB(block)
	metaDataPadded := make([]byte, len(metaDataB64))
	ecbDec.Decrypt(metaDataPadded, metaDataB64)
	metaDataJson := unpad(metaDataPadded)[6:]

	var meta ncmMetadata
	if err := json.Unmarshal(metaDataJson, &meta); err != nil {
		return "", fmt.Errorf("unmarshal metadata: %w", err)
	}
	if _, err := file.Seek(9, io.SeekCurrent); err != nil {
		return "", fmt.Errorf("seek to image: %w", err)
	}

	var imageSize uint32
	if err := binary.Read(file, binary.LittleEndian, &imageSize); err != nil {
		return "", fmt.Errorf("read image size: %w", err)
	}
	imageData := make([]byte, imageSize)
	if _, err := io.ReadFull(file, imageData); err != nil {
		return "", fmt.Errorf("read image data: %w", err)
	}

	chunk := make([]byte, 0x8000)
	var audioBuf bytes.Buffer
	for {
		n, err := file.Read(chunk)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read audio: %w", err)
		}
		for i := range n {
			j := byte(i + 1)
			chunk[i] ^= keyBox[(keyBox[j]+keyBox[(keyBox[j]+j)&0xff])&0xff]
		}
		audioBuf.Write(chunk[:n])
	}

	baseName := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	artist := parseArtist(meta.Artist)
	audioData := audioBuf.Bytes()
	outputPath := filepath.Join(outputDir, baseName+"."+meta.Format)

	if err := os.WriteFile(outputPath, audioData, 0644); err != nil {
		return "", fmt.Errorf("write audio: %w", err)
	}
	preserveCreationTime(inputPath, outputPath)

	if meta.Format == "mp3" {
		if err := embedMP3(outputPath, &meta, artist, imageData); err != nil {
			os.Remove(outputPath)
			return "", fmt.Errorf("embed mp3 metadata: %w", err)
		}
		return "mp3", nil
	} else {
		embedFLAC(outputPath, &meta, artist, imageData)
		return "flac", nil
	}
}
