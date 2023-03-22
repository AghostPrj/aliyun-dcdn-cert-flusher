/**
 * @Author: aghost<ggg17226@gmail.com>
 * @Date: 2023/3/22 13:53
 * @Desc:
 */

package dcdnSite

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dcdn"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"strings"
	"time"
)

type DcdnSite struct {
	AccessKey    string
	AccessSecret string
	Region       string
	CertPath     string
	CertKeyPath  string
	Domain       string

	cert   string
	key    string
	client *dcdn.Client
}

func (s *DcdnSite) ReadCert() error {
	fp, err := os.OpenFile(s.CertPath, os.O_RDONLY, 0444)
	if err != nil {
		return err
	}

	fileContentBytes, err := io.ReadAll(fp)
	if err != nil {
		return err
	}

	fileContentStr := string(fileContentBytes)

	s.cert = fileContentStr

	err = fp.Close()
	if err != nil {
		return err
	}

	fp, err = os.OpenFile(s.CertKeyPath, os.O_RDONLY, 0444)
	if err != nil {
		return err
	}

	fileContentBytes, err = io.ReadAll(fp)
	if err != nil {
		return err
	}

	fileContentStr = string(fileContentBytes)

	s.key = fileContentStr

	return fp.Close()
}

func (s *DcdnSite) CheckClient() error {

	client, err := dcdn.NewClientWithAccessKey(s.Region, s.AccessKey, s.AccessSecret)
	if err != nil {
		return err
	}

	s.client = client

	s.client.Client.GetConfig().Scheme = "HTTPS"

	req := dcdn.CreateDescribeUserDcdnStatusRequest()
	resp, err := s.client.DescribeUserDcdnStatus(req)
	if err != nil {
		return err
	}

	if resp == nil {
		return errors.New("nil resp")
	}

	if !resp.OnService {
		return errors.New("service not on service")
	}

	if !resp.Enabled {
		return errors.New("service not enabled")
	}

	_, err = s.getDomainId()
	if err != nil {
		return err
	}

	return nil
}
func (s *DcdnSite) FlushCert() error {

	err := s.ReadCert()
	if err != nil {
		return err
	}

	fingerprint, err := getCertFingerprint(s.cert)

	if err != nil {
		return err
	}

	expireTime, err := getCertExpireTime(s.cert)
	if err != nil {
		return err
	}

	_, err = s.getDomainId()
	if err != nil {
		return err
	}

	_, remoteCertFingerprint, err := s.getDomainCertNameAndFingerprint()

	if err != nil && err.Error() != "cert info not found" {
		return err
	}

	if remoteCertFingerprint != fingerprint {
		err := s.setCert()
		if err != nil {
			return err
		}

		log.WithFields(log.Fields{
			"op":         "FlushCert",
			"step":       "upload cert",
			"new_expire": expireTime,
			"domain":     s.Domain,
		}).Info()
	} else {
		log.WithFields(log.Fields{
			"op":                 "FlushCert",
			"step":               "check cert",
			"status":             "same as remote",
			"fingerprint_sha256": fingerprint,
			"domain":             s.Domain,
		}).Debug()
	}

	return nil
}

func (s *DcdnSite) getDomainId() (int64, error) {
	req := dcdn.CreateDescribeDcdnUserDomainsRequest()
	req.PageSize = "50"
	req.DomainStatus = "online"
	req.DomainSearchType = "full_match"
	req.DomainName = s.Domain

	resp, err := s.client.DescribeDcdnUserDomains(req)
	if err != nil {
		return 0, err
	}

	if resp == nil {
		return 0, errors.New("nil resp")
	}

	result := int64(0)

	for _, dm := range resp.Domains.PageData {
		if dm.DomainStatus == "online" && dm.SSLProtocol == "on" &&
			strings.ToLower(dm.DomainName) == s.Domain {
			result = dm.DomainId
			break
		}

	}

	if result < 1 {
		return 0, errors.New("domain not found")
	}

	return result, err

}

func (s *DcdnSite) getDomainCertNameAndFingerprint() (string, string, error) {
	req := dcdn.CreateDescribeDcdnDomainCertificateInfoRequest()
	req.DomainName = s.Domain

	resp, err := s.client.DescribeDcdnDomainCertificateInfo(req)
	if err != nil {
		return "", "", err
	}

	if resp == nil {
		return "", "", errors.New("nil resp")
	}

	if len(resp.CertInfos.CertInfo) < 1 {
		return "", "", errors.New("cert info not found")
	}

	info := resp.CertInfos.CertInfo[0]
	fingerprint, err := getCertFingerprint(info.SSLPub)
	if err != nil {
		return "", "", err
	}

	return info.CertName, fingerprint, nil
}

func (s *DcdnSite) setCert() error {
	newUUID, err := uuid.NewUUID()
	if err != nil {
		return err
	}

	certName := newUUID.String()

	req := dcdn.CreateSetDcdnDomainCertificateRequest()
	req.DomainName = s.Domain
	req.CertName = certName
	req.CertType = "upload"
	req.SSLProtocol = "on"
	req.SSLPub = s.cert
	req.SSLPri = s.key
	req.ForceSet = "1"

	resp, err := s.client.SetDcdnDomainCertificate(req)
	if err != nil {
		return err
	}

	if resp == nil {
		return errors.New("nil resp")
	}
	return nil

}
func getCertFingerprint(certStr string) (string, error) {
	decodedPem, _ := pem.Decode([]byte(certStr))

	cert, err := x509.ParseCertificate(decodedPem.Bytes)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(cert.Raw)

	return fmt.Sprintf("%x", sum), err
}
func getCertExpireTime(certStr string) (*time.Time, error) {
	decodedPem, _ := pem.Decode([]byte(certStr))

	cert, err := x509.ParseCertificate(decodedPem.Bytes)
	if err != nil {
		return nil, err
	}

	return &cert.NotAfter, nil

}
