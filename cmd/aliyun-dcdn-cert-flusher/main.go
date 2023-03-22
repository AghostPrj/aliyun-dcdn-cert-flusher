/**
 * @Author: aghost<ggg17226@gmail.com>
 * @Date: 2023/3/22 13:08
 * @Desc:
 */

package main

import (
	"github.com/AghostPrj/aliyun-dcdn-cert-flusher/internal/global"
	"github.com/AghostPrj/aliyun-dcdn-cert-flusher/internal/initializator"
	"github.com/AghostPrj/aliyun-dcdn-cert-flusher/internal/object/dcdnSite"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

func main() {
	initializator.InitApp()

	time.Sleep(time.Minute)

	for {

		wg := sync.WaitGroup{}
		wg.Add(len(global.DcdnSites))

		for _, site := range global.DcdnSites {
			go func(s *dcdnSite.DcdnSite) {
				defer wg.Done()
				err := s.FlushCert()
				if err != nil {
					log.WithFields(log.Fields{
						"op":   "do_flush_cert",
						"site": "",
						"err":  err,
					}).Error()
				}
			}(site)
		}
		wg.Wait()

		time.Sleep(time.Hour)
	}

}
