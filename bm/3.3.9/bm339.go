// Package bm339 implements Akamai BMP 3.3.9 sensor generation.
// RSA modulus is *unchanged* from earlier versions.
package bm339

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/rand"

	dm "xvertile/akamai-bmp/dm"
	"xvertile/akamai-bmp/sdk"
)

// BMP metadata
var (
	BMPVERSION = "3.3.9"
	rsaKey     = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMUymkqr6SQfxqefXMdkI6E1tDzHispEm4WhZAfIWjhvEqfStzy16HvCjIBX2SRpn5pqW2w1TxqyxRnJOe4NEskWGdYY2y4JiD9vpYpWB54u6TOnKutXn2LzjMrvfIJpVXYZ5LYtD1ZUaeTKPz6qELXmBNcSfh/kGLiP8AH4eWKwIDAQAB"
)

type BotManager struct {
	app, lang     string
	challenge     bool
	challengeURL  string
	siteUrl       string
	abck          string
	bmSz          string
	deviceManager dm.DeviceManager
	device        dm.Device
}

func NewStable(app, lang string, ch bool, powURL string, siteUrl string, abck string, bmSz string, dmgr dm.DeviceManager) *BotManager {
	return &BotManager{
		app:           app,
		lang:          lang,
		challenge:     ch,
		challengeURL:  powURL,
		siteUrl:       siteUrl,
		abck:          abck,
		bmSz:          bmSz,
		deviceManager: dmgr,
		device:        dmgr.RandomAndroidDevice(),
	}
}

func (bm *BotManager) GetAndroidId() string          { return bm.device.AndroidID }
func (bm *BotManager) GetDevice() dm.Device          { return bm.device }
func (bm *BotManager) GetPowToken() string           { return sdk.RandomHex(64) }
func (bm *BotManager) GetPowResponse() (string, error) {
	if !bm.challenge {
		return "", nil
	}
	params, err := sdk.GetPowParams(
		bm.device.UserAgent(BMPVERSION, bm.lang),
		sdk.GetCfDate()-int64(sdk.RandomInt(6600, 50000)),
		bm.device.AndroidID,
		bm.siteUrl,
	)
	if err != nil {
		return "", err
	}
	return sdk.GeneratePow(*params)
}

func (bm *BotManager) GenerateSensorData() (string, error) {
	var (
		sensorData           []sdk.Pair
		tact, eact           string
		touchVel, touchSteps int
	)

	var orientationData, oreintationTimeData string
	var d int64
	var orientationCount int

	userAgent := bm.device.UserAgent(BMPVERSION, bm.lang)
	if bm.siteUrl != "" {
		userAgent = userAgent + "|site:" + bm.siteUrl
	}
	if bm.abck != "" {
		userAgent = userAgent + "|abck:" + bm.abck
	}
	if bm.bmSz != "" {
		userAgent = userAgent + "|bmsz:" + bm.bmSz
	}

	motionData, d2, motionCount := sdk.GenerateMotionString(int(sdk.BitLengthShift(uint64(sdk.RandomInt(32, 128)))))
	tact, touchVel, touchSteps = bm.GenerateTouchEvents()
	motionTimeArr := sdk.GenTimeEvent(motionCount)
	motionTimeData := sdk.CreateMotionPair(motionTimeArr, 0.0).Id.(string)

	sensorData = append(sensorData, sdk.Pair{Id: "", Value: BMPVERSION})
	sensorData = append(sensorData, sdk.Pair{Id: "-70", Value: "{}"})
	sensorData = append(sensorData, sdk.Pair{Id: "-80", Value: "{}"})
	sensorData = append(sensorData, sdk.Pair{Id: "-100", Value: userAgent})
	sensorData = append(sensorData, sdk.Pair{Id: "-101", Value: bm.GetEventListeners()})
	sensorData = append(sensorData, sdk.Pair{Id: "-102", Value: eact})

	bgEvents := bm.GetBackgroundEvents()
	if bgEvents == "" {
		bgEvents = "2,0;3,100;"
	}
	sensorData = append(sensorData, sdk.Pair{Id: "-103", Value: bgEvents})

	sensorData = append(sensorData, sdk.Pair{Id: "-108", Value: ""})
	sensorData = append(sensorData, sdk.Pair{Id: "-112", Value: bm.GetPrefBench()})
	sensorData = append(sensorData, sdk.Pair{Id: "-115", Value: bm.GetVerifyStats(touchVel, touchSteps, int(d), int(d2), orientationCount, motionCount)})
	sensorData = append(sensorData, sdk.Pair{Id: "-117", Value: tact})
	sensorData = append(sensorData, sdk.Pair{Id: "-120", Value: bm.abck})
	sensorData = append(sensorData, sdk.Pair{Id: "-121", Value: bm.bmSz})
	sensorData = append(sensorData, sdk.Pair{Id: "-144", Value: oreintationTimeData})
	sensorData = append(sensorData, sdk.Pair{Id: "-142", Value: orientationData})
	sensorData = append(sensorData, sdk.Pair{Id: "-145", Value: motionTimeData})
	sensorData = append(sensorData, sdk.Pair{Id: "-143", Value: motionData})
	sensorData = append(sensorData, sdk.Pair{Id: "-150", Value: fmt.Sprintf("%v,%v", 1, 1)})

	encryptedSensor, err := bm.EncryptSensor([]byte(sdk.SerializeBmp(sensorData)))
	if err != nil {
		panic(err)
	}

	powResponse, err := bm.GetPowResponse()
	if err != nil {
		return "", err
	}
	powToken := bm.GetPowToken()

	trailingNumbers := fmt.Sprintf("%d,%d,%d", touchVel, touchSteps, motionCount)

	sensor := fmt.Sprintf("6,a,%s,%s,%s$%s$$$", encryptedSensor, powResponse, powToken, trailingNumbers)
	return sensor, nil
}

func (bm *BotManager) GenerateTouchEvents() (string, int, int) {
	tact := ""
	count := sdk.RandomInt(5, 10) // Increased for BMP 3.3.9 realism
	vel := 0

	for i := 0; i < count; i++ {
		time := int(math.Round(30 * rand.Float64()))
		action := 1

		if i == 0 || rand.Float64() >= 0.75 {
			time = int(math.Round(1500 * rand.Float64()))
			action = 2
			tact += fmt.Sprintf("%v,%v,0,0,1,1,1,-1;", action, time)
		} else if sdk.RandomBool() {
			action = 3
			tact += fmt.Sprintf("%v,%v,0,0,1,1,1,-1;", action, time)
		} else {
			tact += fmt.Sprintf("%v,%v,0,0,1,1,1,-1;", action, time)
		}
		vel = vel + time + action
	}

	return tact, vel, count
}

func (bm *BotManager) GetSystemInfo() string     { return sdk.SystemInfo(bm.device) }
func (bm *BotManager) GetEventListeners() string { return sdk.EventListeners() }
func (bm *BotManager) GetBackgroundEvents() string {
	if s := sdk.BackgroundEvents(); s != "" { return s }
	return "2,0;3,100;"
}
func (bm *BotManager) GetPrefBench() string      { return sdk.PrefBench() }
func (bm *BotManager) GetVerifyStats(vel, steps, d, d2, orientationCount, motionCount int) string {
	return fmt.Sprintf("%d,%d,0,0,0,0,%d,%d,%d,%d,%d", vel, steps, d, d2, orientationCount, motionCount, sdk.RandomInt(5, 14))
}
func (bm *BotManager) GetSensorCal() string   { return sdk.SensorCal() }
func (bm *BotManager) GetGyroDrift() string   { return sdk.GyroDrift() }
func (bm *BotManager) GetMemStats() string    { return sdk.MemStats() }
func (bm *BotManager) GetScheduler() string   { return sdk.Scheduler() }

func (bm *BotManager) EncryptSensor(buf []byte) (string, error) {
	aesKey := sdk.RandomBytes(16)
	iv := sdk.RandomBytes(16)
	cipher, err := sdk.AESCBCEncrypt(buf, aesKey, iv)
	if err != nil {
		return "", err
	}
	wrapped, err := sdk.RSAEncryptOAEP(append(aesKey, iv...), rsaKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(wrapped) + "." +
		base64.StdEncoding.EncodeToString(cipher), nil
} 