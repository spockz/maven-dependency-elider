// WHY: Drives the real runtime downloader against deterministic loopback responses.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

const discoHost = "api.foojay.io"

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: runtime-download-fixture directory certificate")
	}
	config, err := discoveryTLS(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	baseURL := "http://" + listener.Addr().String()
	files := http.FileServer(http.Dir(os.Args[1]))
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodConnect {
				if err := serveDiscovery(response, request, config, baseURL); err != nil {
					log.Print(err)
				}
				return
			}
			log.Printf("download %s", request.URL.Path)
			files.ServeHTTP(response, request)
		}),
	}
	fmt.Println(listener.Addr())
	log.Fatal(server.Serve(listener))
}

func discoveryTLS(certificateFile string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	certificate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: discoHost},
		DNSNames:              []string{discoHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	}), 0600); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, nil
}

func serveDiscovery(response http.ResponseWriter, request *http.Request, config *tls.Config, baseURL string) error {
	if request.Host != discoHost+":443" {
		http.Error(response, "Unexpected discovery destination", http.StatusBadGateway)
		return errors.New("unexpected discovery destination " + request.Host)
	}
	connection, stream, err := http.NewResponseController(response).Hijack()
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	if _, err := stream.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	if err := stream.Flush(); err != nil {
		return err
	}
	local := tls.Server(connection, config)
	query, err := http.ReadRequest(bufio.NewReader(local))
	if err != nil {
		return err
	}
	status, result := discoResponse(query, baseURL)
	body, err := json.Marshal(map[string]any{"result": result})
	if err != nil {
		return err
	}
	reply := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	return reply.Write(local)
}

func discoResponse(request *http.Request, baseURL string) (int, []map[string]any) {
	log.Print(request.URL.RequestURI())
	switch request.URL.Path {
	case "/disco/v3.0/packages":
		if request.URL.Query().Get("version") == "21.0.999" {
			return http.StatusOK, []map[string]any{}
		}
		return http.StatusOK, []map[string]any{
			{"id": "first", "filename": "first.zip", "directly_downloadable": true},
			{"id": "second", "filename": "second.zip", "directly_downloadable": true},
		}
	case "/disco/v3.0/ids/first":
		return http.StatusOK, []map[string]any{
			{"filename": "first.zip", "direct_download_uri": baseURL + "/runtime.zip"},
		}
	default:
		return http.StatusNotFound, []map[string]any{}
	}
}
