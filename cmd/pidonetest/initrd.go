package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cavaliergopher/cpio"
)

type Archive struct {
	name   string
	writer *cpio.Writer
}

func NewArchive(file *os.File) *Archive {
	return &Archive{
		name:   file.Name(),
		writer: cpio.NewWriter(file),
	}
}

func (a *Archive) AddFile(fileName string, altName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("open file: %v", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("read info: %v", err)
	}

	cpioHdr, err := cpio.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("create cpio header: %v", err)
	}

	if info.IsDir() {
		cpioHdr.Links = 2
	}

	if altName != "" {
		cpioHdr.Name = altName
	} else if fileName != cpioHdr.Name {
		cpioHdr.Name, _ = strings.CutPrefix(fileName, "/usr/")
	}

	if err := a.writer.WriteHeader(cpioHdr); err != nil {
		return fmt.Errorf("write cpio header: %v", err)
	}

	if !info.IsDir() {
		if _, err := io.Copy(a.writer, file); err != nil {
			return fmt.Errorf("write cpio body: %v", err)
		}
	}

	return nil
}

func (a *Archive) Close() error {
	if a == nil {
		return nil
	}
	return a.writer.Close()
}

func (a *Archive) Remove() error {
	if a == nil {
		return nil
	}
	_ = a.Close()
	return os.Remove(a.name)
}

func createInitrd(initFilePath string, additionalFiles ...string) (string, error) {
	initrdFile, err := os.CreateTemp("", "go_pidonetest_initrd")
	if err != nil {
		return "", fmt.Errorf("create file")
	}
	defer initrdFile.Close()

	initrd := NewArchive(initrdFile)
	defer initrd.Close()

	if err := initrd.AddFile(".", ""); err != nil {
		_ = initrd.Remove()
		return "", err
	}
	if err := initrd.AddFile(initFilePath, "init"); err != nil {
		_ = initrd.Remove()
		return "", err
	}

	for _, file := range additionalFiles {
		if err := initrd.AddFile(file, ""); err != nil {
			_ = initrd.Remove()
			return "", err
		}
	}

	return initrdFile.Name(), nil
}
