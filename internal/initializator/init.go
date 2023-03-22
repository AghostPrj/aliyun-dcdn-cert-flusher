/**
 * @Author: aghost<ggg17226@gmail.com>
 * @Date: 2023/3/22 13:09
 * @Desc:
 */

package initializator

import (
	"github.com/AghostPrj/aliyun-dcdn-cert-flusher/internal/constData"
	"github.com/AghostPrj/aliyun-dcdn-cert-flusher/internal/global"
	"github.com/AghostPrj/aliyun-dcdn-cert-flusher/internal/object/dcdnSite"
	"github.com/ggg17226/aghost-go-base/pkg/utils/configUtils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"strings"
)

func InitApp() {
	configUtils.SetConfigFileName(constData.ApplicationName)

	configUtils.InitConfigAndLog()
	confMapArr := viper.Get("sites")

	if confMapArr == nil {
		log.WithFields(log.Fields{
			"op":   "InitApp",
			"step": "check sites config",
			"err":  "sites conf error",
		}).Panic()
	}

	if siteConfigs, ok := confMapArr.([]interface{}); ok {

		if len(siteConfigs) < 1 {
			log.WithFields(log.Fields{
				"op":   "InitApp",
				"step": "check sites config",
				"err":  "sites conf error",
			}).Panic()
		}

		for _, rawSiteConf := range siteConfigs {

			if siteConf, ok := rawSiteConf.(map[string]interface{}); ok {

				ds := new(dcdnSite.DcdnSite)

				ds.AccessKey = getConfString(&siteConf, "access_key")
				ds.AccessSecret = getConfString(&siteConf, "access_secret")
				ds.CertPath = getConfString(&siteConf, "cert_path")
				ds.CertKeyPath = getConfString(&siteConf, "cert_key")
				ds.Domain = strings.ToLower(getConfString(&siteConf, "domain"))
				ds.Region = getRegion(&siteConf)

				global.DcdnSites = append(global.DcdnSites, ds)

			} else {
				log.WithFields(log.Fields{
					"op":   "InitApp",
					"step": "check site config",
					"err":  "site conf error",
				}).Panic()
			}

		}

	} else {
		log.WithFields(log.Fields{
			"op":   "InitApp",
			"step": "check sites config",
			"err":  "sites conf error",
		}).Panic()
	}

	for _, site := range global.DcdnSites {

		err := site.ReadCert()
		if err != nil {
			log.WithFields(log.Fields{
				"op":            "InitApp",
				"step":          "check sites cert config",
				"err":           err,
				"cert_file":     site.CertPath,
				"cert_key_file": site.CertKeyPath,
			}).Panic()
		}

		err = site.CheckClient()
		if err != nil {
			log.WithFields(log.Fields{
				"op":         "InitApp",
				"step":       "check sites aliyun access config",
				"err":        err,
				"access_key": site.AccessKey,
			}).Panic()
		}

	}

	log.WithField("sites_num", len(global.DcdnSites)).Info()

}
func getConfString(configMap *map[string]interface{}, key string) string {
	if d, ok := (*configMap)[key]; ok {
		if str, ok := d.(string); ok {
			return str
		} else {
			log.WithFields(log.Fields{
				"op":   "InitApp",
				"step": "check sites config",
				"err":  key + " conf error",
			}).Panic()
		}
	} else {
		log.WithFields(log.Fields{
			"op":   "InitApp",
			"step": "check sites config",
			"err":  key + " conf error",
		}).Panic()
	}

	return ""
}
func getRegion(configMap *map[string]interface{}) string {
	defaultRegion := "cn-shanghai"
	key := "region"
	if d, ok := (*configMap)[key]; ok {
		if str, ok := d.(string); ok {
			return str
		} else {
			return defaultRegion
		}
	} else {
		return defaultRegion
	}
}
