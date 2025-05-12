// Package bm402 implements Akamai BMP 4.0.2 sensor generation.
// RSA modulus is *unchanged* from earlier versions.
package bm402

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/rand"
	dm "xvertile/akamai-bmp/dm"
	"xvertile/akamai-bmp/sdk"
)

// BMP metadata
const (
	BMPVersion = "4.0.2"
	// identical modulus (2048‑bit) – kept for completeness
	rsaKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMUymkqr6SQfxqefXMdkI6E1tDzHispEm4WhZAfIWjhvEqfStzy16HvCjI" +
		"BX2SRpn5pqW2w1TxqyxRnJOe4NEskWGdYY2y4JiD9vpYpWB54u6TOnKutXn2LzjMrvfIJpVXYZ5LYtD1ZUaeTKPz6qELXmBNcSfh/kGLiP8AH4eWKwIDAQAB"
)

// BotManager satisfies AkamaiBmpGen.
type BotManager struct {
	app, lang     string
	challenge     bool
	challengeURL  string
	deviceManager dm.DeviceManager
	device        dm.Device
}

// NewStable returns a generator wired for realistic entropy.
func NewStable(app, lang string, ch bool, powURL string, dmgr dm.DeviceManager) *BotManager {
	return &BotManager{
		app:           app,
		lang:          lang,
		challenge:     ch,
		challengeURL:  powURL,
		deviceManager: dmgr,
		device:        dmgr.RandomAndroidDevice(),
	}
}

func (bm *BotManager) GetAndroidId() string          { return bm.device.AndroidID }
func (bm *BotManager) GetDevice() dm.Device          { return bm.device }
func (bm *BotManager) GetPowToken() string           { return sdk.RandomHex(64) } // unchanged
func (bm *BotManager) GetPowResponse() (string, error) {
	if !bm.challenge {
		return "", nil
	}
	params, err := sdk.GetPowParams(bm.device.UserAgent(BMPVersion, bm.lang), sdk.GetCfDate()-int64(sdk.RandomInt(6600, 50000)), bm.device.AndroidID, bm.challengeURL)
	if err != nil {
		return "", err
	}
	return sdk.GeneratePow(*params)
}

// ---------------------------------------------------------------------
//                             Sensor Logic
// ---------------------------------------------------------------------
func (bm *BotManager) GenerateSensorData() (string, error) {
	var data []sdk.Pair

	// field‑order slice for 4.0.2
	data = append(data,
		sdk.Pair{"", BMPVersion},
		sdk.Pair{"-70", "{}"},
		sdk.Pair{"-82", "{}"}, // was -80
		sdk.Pair{"-100", sdk.SystemInfo(bm.device)},
		sdk.Pair{"-101", sdk.EventListeners()},
		sdk.Pair{"-103", sdk.BackgroundEvents()},
		sdk.Pair{"-108", ""},
		sdk.Pair{"-113", sdk.PrefBench()}, // was -112
	)

	// ─── Human‑interaction entropy ────────────────────────────────
	tact, vel, steps := bm.generateTouch()
	data = append(data,
		sdk.Pair{"-115", bm.GetVerifyStats(vel, steps)},
		sdk.Pair{"-117", tact},
	)

	// new calibration IDs
	data = append(data,
		sdk.Pair{"-160", sdk.SensorCal()},
		sdk.Pair{"-161", sdk.GyroDrift()},
		sdk.Pair{"-162", sdk.MemStats()},
		sdk.Pair{"-163", sdk.Scheduler()},
	)

	plain := sdk.SerializeBmp(data)
	enc, err := bm.encryptSensor([]byte(plain))
	if err != nil {
		return "", err
	}
	pow, err := bm.GetPowResponse()
	if err != nil {
		return "", err
	}
	return enc + "$" + pow + "$" + bm.GetPowToken(), nil
}

// ---------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------
func (bm *BotManager) generateTouch() (tact string, velocity, steps int) {
	steps = sdk.RandomInt(6, 12) // slightly higher than 3.3.9
	for i := 0; i < steps; i++ {
		time := int(math.Round(35 * rand.Float64()))
		action := 1
		if i == 0 || rand.Float64() >= 0.75 {
			time = int(math.Round(1500 * rand.Float64()))
			action = 2
		} else if sdk.RandomBool() {
			action = 3
		}
		tact += fmt.Sprintf("%d,%d,0,0,1,1,1,-1;", action, time)
		velocity += time + action
	}
	return
}

// ─── Stub helpers (identical logic to earlier versions) ──────────────
func (bm *BotManager) GetVerifyStats(vel, steps int) string {
	return fmt.Sprintf("%d,%d,0,0,0,0,%d", vel, steps, sdk.RandomInt(5, 14))
}

// encryptSensor wraps SerializeBmp → AES‑CBC → RSA‑wrap (same as 3.3.x).
func (bm *BotManager) encryptSensor(buf []byte) (string, error) {
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