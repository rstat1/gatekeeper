package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"time"

	"os"

	"github.com/sirupsen/logrus"
)

// APIResponse ...
type APIResponse struct {
	Status         string `json:"status"`
	Response       string `json:"response"`
	HttpStatusCode int    `json:"-"`
}

// LocalAppConfig ...
type LocalAppConfig struct {
	DBName              string `json:"db"`
	DBServer            string `json:"dbServer"`
	GatekeeperAPIAddr   string `json:"gatekeeperAddr"`
	RedisAddr           string `json:"redisAddr"`
	S3Endpoint          string `json:"s3Endpoint"`
	VaultEndpoint       string `json:"vaultEndpoint"`
	ImmichAlbumID       string `json:"immichAlbumID"`
	ImgCacheBucket      string `json:"imgCacheBucket"`
	ImmichEndpoint      string `json:"immichEndpoint"`
	WeatherLocation     string `json:"weatherLocation"`
	S3SecretName        string `json:"s3CredsSecretName"`
	ImmichAPIKeySecret  string `json:"immichAPIKeySecret"`
	WeatherAPI          string `json:"weatherAPI"`
	WeatherAPIKeySecret string `json:"weatherAPIKeySecret"`
}

var (
	DevMode               bool
	Logger                *logrus.Logger
	BaseURL               string
	BaseAPIURL            string
	BaseAuthURL           string
	InternalAPIURL        string
	InternalBaseURL       string
	Config                LocalAppConfig
	WeatherLocationBase64 string
	currentProcessName    string
	s3KeyID               string
	s3Secret              string
)

// CreateAPIResponse ...
func CreateAPIResponse(response string, err error, failureCode int) APIResponse {
	if err == nil {
		return APIResponse{
			Status:         "success",
			Response:       response,
			HttpStatusCode: http.StatusOK,
		}
	} else {
		return APIResponse{
			Status:         "failed",
			Response:       err.Error(),
			HttpStatusCode: failureCode,
		}
	}
}

// CreateAPIRespFromObject ...
func CreateAPIRespFromObject(response interface{}, err error, failureCode int) APIResponse {
	rAsJSON, _ := json.Marshal(response)
	return CreateAPIResponse(string(rAsJSON), err, failureCode)
}

// CreateAPIRespWithStatusCode ...
func CreateAPIRespWithStatusCode(response string, err error, statusCode int) APIResponse {
	if err == nil {
		return APIResponse{
			Status:         "success",
			Response:       response,
			HttpStatusCode: statusCode,
		}
	} else {
		return APIResponse{
			Status:         "failed",
			Response:       err.Error(),
			HttpStatusCode: http.StatusInternalServerError,
		}
	}
}

// WriteAPIResponseStruct ...
func WriteAPIResponseStruct(writer http.ResponseWriter, resp APIResponse) {
	writeCommonHeaders(writer)
	writer.Header().Add("Content-Type", "application/json")
	writer.WriteHeader(resp.HttpStatusCode)
	apiResp, _ := json.Marshal(resp)
	writer.Write([]byte(apiResp))
}

// WriteFailureResponse ..
func WriteFailureResponse(err error, resp http.ResponseWriter, functionName string, status int) {
	LogError(functionName, err)
	WriteAPIResponseStruct(resp, CreateAPIResponse("failed", err, status))
}

// WriteResponse ...
func WriteResponse(respWriter http.ResponseWriter, resp interface{}, err error, failureCode int) {
	if err != nil {
		LogError("", err)
		WriteAPIResponseStruct(respWriter, CreateAPIResponse("failed", err, failureCode))
	} else {
		writeCommonHeaders(respWriter)
		respWriter.WriteHeader(200)
		var apiResp []byte
		var e error

		if str, ok := resp.(string); ok {
			apiResp = []byte(str)
		} else {
			apiResp, e = json.Marshal(resp)
			if e != nil {
				LogError("", e)
			}
		}
		respWriter.Write(apiResp)
	}
}

// WriteResponseWithCookie ...
func WriteResponseWithCookie(respWriter http.ResponseWriter, resp interface{}, cookieName, cookieValue string) {
	// writeCommonHeaders(respWriter)
	// respWriter.WriteHeader(200)
	var apiResp []byte
	var e error

	if str, ok := resp.(string); ok {
		apiResp = []byte(str)
	} else {
		apiResp, e = json.Marshal(resp)
		if e != nil {
			LogError("", e)
		}
	}
	http.SetCookie(respWriter, &http.Cookie{Name: cookieName, Value: cookieValue})

	respWriter.Write(apiResp)

}

// CreateFailureResponse ...
func CreateFailureResponse(err error, functionName string, status int) APIResponse {
	LogError(functionName, err)
	return CreateAPIResponse("failed", err, status)
}

// CreateFailureResponseWithFields ...
func CreateFailureResponseWithFields(err error, status int, fields logrus.Fields) APIResponse {
	Logger.WithFields(fields).Errorln(err)
	return CreateAPIResponse("failed", err, status)
}

func ConvertUpdateResultToAPIResp(result string, err error) APIResponse {
	if result == "not modified" && err == nil {
		return CreateAPIResponse("failed", errors.New("not modified"), 304)
	} else if result == "not found" {
		return CreateAPIResponse("failed", errors.New("not found"), 404)
	} else if err != nil {
		return CreateAPIResponse("failed", err, 500)
	}

	return CreateAPIResponse("success", nil, 200)
}

// ValidatePOSTRequest ...
func ValidatePOSTRequest(validator func(*http.Request) APIResponse, handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == "POST" && request.Header.Get("Content-Length") == "" {
			WriteAPIResponseStruct(writer, CreateAPIResponse("", errors.New("request body empty"), 400))
		} else {
			if resp := validator(request); resp.Status == "success" {
				handler(writer, request)
			} else {
				WriteAPIResponseStruct(writer, resp)
			}
		}
	})
}

// BasicAuthRequired Forces the requestor to collect a username/password combo via WWW-Auth
// The provided validator function should then take that combo and insure that it's a valid combo.
// Then we call the handler, to do whatever the handler does
func BasicAuthRequired(validator func(string, string) (bool, error), handler func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		if authHeader := req.Header.Get("Authorization"); strings.Contains(authHeader, "Basic") == true {
			if success, err := validator(strings.Replace(authHeader, "Basic ", "", 1), req.Method); success {
				handler(writer, req)
			} else {
				if err != nil {
					http.Error(writer, err.Error(), http.StatusForbidden)
				} else {
					http.Error(writer, "cred validation failed", http.StatusForbidden)
				}
			}
		} else {
			writer.Header().Add("WWW-Authenticate", "Basic realm="+`"devcentral"`)
			http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		}
	})
}

// RequestWrapper ...
func RequestWrapper(validator func(*http.Request) APIResponse, validMethod string, handler func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if (validMethod != "") && (request.Method != validMethod) {
			WriteAPIResponseStruct(writer, APIResponse{
				Status:         "failed",
				Response:       "method not allowed",
				HttpStatusCode: http.StatusMethodNotAllowed,
			})
		} else {
			if resp := validator(request); resp.Status == "success" {
				handler(writer, request)
			} else {
				WriteAPIResponseStruct(writer, resp)
			}
		}
	})
}

// ValidateRequestMethod ...
func ValidateRequestMethod(r *http.Request, validMethod string, writer http.ResponseWriter) bool {
	if r.Method != validMethod {
		WriteAPIResponseStruct(writer, APIResponse{
			Status:         "failed",
			Response:       "method not allowed",
			HttpStatusCode: http.StatusMethodNotAllowed,
		})
		return false
	} else {
		return true
	}
}
func writeCommonHeaders(writer http.ResponseWriter) {
	writer.Header().Add("Content-Type", "application/json")
}

// Nothing ...
func Nothing(r *http.Request) APIResponse {
	return CreateAPIResponse("success", nil, 200)
}

// InitLogrus ...
func InitLogrus() {
	Logger = logrus.New()
	Logger.Out = os.Stderr
	Logger.SetLevel(logrus.DebugLevel)
	currentProcessName = os.Args[0]
}

func PanicOnError(e error) {
	if e != nil {
		panic(e)
	}
}

// LogError ...
func LogError(extra string, err error) error {
	if err != nil {
		pc, _, line, _ := runtime.Caller(1)
		funcObj := runtime.FuncForPC(pc)
		runtimeFunc := regexp.MustCompile(`^.*\.(.*)$`)
		name := runtimeFunc.ReplaceAllString(funcObj.Name(), "$1")

		if extra != "" {
			Logger.WithFields(logrus.Fields{"func": name, "line": line, "extra": extra, "process": currentProcessName}).Errorln(err)
		} else {
			Logger.WithFields(logrus.Fields{"func": name, "line": line, "process": currentProcessName}).Errorln(err)
		}
		return err
	}
	return nil
}

// LogDebug ...
func LogDebug(extraKey string, extraValue interface{}, entry interface{}) {
	pc, _, line, _ := runtime.Caller(1)
	funcObj := runtime.FuncForPC(pc)
	runtimeFunc := regexp.MustCompile(`^.*\.(.*)$`)
	name := runtimeFunc.ReplaceAllString(funcObj.Name(), "$1")

	if extraKey != "" {
		Logger.WithFields(logrus.Fields{extraKey: extraValue, "func": name, "line": line, "process": currentProcessName}).Debugln(entry)
	} else {
		Logger.WithFields(logrus.Fields{"func": name, "line": line, "process": currentProcessName}).Debugln(entry)
	}
}

// LogInfo ...
func LogInfo(extraKey string, extraValue interface{}, entry interface{}) {
	pc, _, line, _ := runtime.Caller(1)
	funcObj := runtime.FuncForPC(pc)
	runtimeFunc := regexp.MustCompile(`^.*\.(.*)$`)
	name := runtimeFunc.ReplaceAllString(funcObj.Name(), "$1")

	if extraKey != "" {
		Logger.WithFields(logrus.Fields{extraKey: extraValue, "func": name, "line": line, "process": currentProcessName}).Infoln(entry)
	} else {
		Logger.WithFields(logrus.Fields{"func": name, "line": line, "process": currentProcessName}).Infoln(entry)
	}
}

// LogWarn ...
func LogWarn(extraKey string, extraValue interface{}, entry interface{}) {
	pc, _, line, _ := runtime.Caller(1)
	funcObj := runtime.FuncForPC(pc)
	runtimeFunc := regexp.MustCompile(`^.*\.(.*)$`)
	name := runtimeFunc.ReplaceAllString(funcObj.Name(), "$1")
	if extraKey != "" {
		Logger.WithFields(logrus.Fields{"func": name, "line": line, extraKey: extraValue, "process": currentProcessName}).Warnln(entry)
	} else {
		Logger.WithFields(logrus.Fields{"func": name, "line": line, "process": currentProcessName}).Warnln(entry)
	}
}

// CommonProcessInit ...
func CommonProcessInit(dev, loadConfig bool) {
	InitLogrus()
	BaseURL = "alargerobot.dev"
	InternalBaseURL = "frost.m"
	if dev {
		InternalAPIURL = "http://api." + InternalBaseURL
	} else {
		InternalAPIURL = "https://api." + BaseURL
	}
	BaseAPIURL = "https://rpc-gw." + BaseURL

	if loadConfig {
		if file, err := os.ReadFile("config.json"); err == nil {
			err = json.Unmarshal([]byte(file), &Config)
			if err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	} else {
		Config = LocalAppConfig{
			DBName:              os.Getenv("DB"),
			DBServer:            os.Getenv("DB_SERVER"),
			RedisAddr:           os.Getenv("REDIS_ADDR"),
			S3Endpoint:          os.Getenv("S3_ENDPOINT"),
			WeatherAPI:          os.Getenv("WEATHER_API"),
			S3SecretName:        os.Getenv("S3_SECRET_NAME"),
			VaultEndpoint:       os.Getenv("VAULT_ENDPOINT"),
			ImgCacheBucket:      os.Getenv("S3_BUCKET_NAME"),
			ImmichAlbumID:       os.Getenv("IMMICH_ALBUM_ID"),
			ImmichEndpoint:      os.Getenv("IMMICH_ENDPOINT"),
			WeatherLocation:     os.Getenv("WEATHER_LOCATION"),
			GatekeeperAPIAddr:   os.Getenv("GATEKEEPER_ADDRESS"),
			ImmichAPIKeySecret:  os.Getenv("IMMICH_API_KEY_SECRET"),
			WeatherAPIKeySecret: os.Getenv("WEATHER_API_KEY_SECRET"),
		}
	}
	WeatherLocationBase64 = ToBase64String(Config.WeatherLocation)
}

// ToSHA256Bytes ...
func ToSHA256String(input []byte) string {
	b := sha256.Sum256(input)
	return hex.EncodeToString(b[:])
}

func ToBase64String(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

// Contains returns true if "s" contains "e"
func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// Remove removes "r" from "s" and returns the new "s"
func Remove(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

// TimeTrack ...
// https://stackoverflow.com/questions/45766572
func TimeTrack(start time.Time) {
	if DevMode {
		elapsed := time.Since(start)
		pc, _, _, _ := runtime.Caller(1)
		funcObj := runtime.FuncForPC(pc)
		runtimeFunc := regexp.MustCompile(`^.*\.(.*)$`)
		name := runtimeFunc.ReplaceAllString(funcObj.Name(), "$1")
		Logger.WithFields(logrus.Fields{"elaspsed": elapsed, "func": name}).Debugln("done")
	}
}

// RandomID ...
// https://stackoverflow.com/questions/12771930
func RandomID(n int) string {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func RandomBytes(n int) []byte {
	var bytes = make([]byte, n)
	rand.Read(bytes)
	return bytes
}

// ConvertInterfaceArrToIntArr ...
func ConvertInterfaceArrToIntArr(from []interface{}) (to []int) {
	to = make([]int, len(from))
	for i, v := range from {
		to[i] = v.(int)
	}
	return to
}

func GetOutboundIP() string {
	netInterfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		LogError("", err)
		return ""
	}
	for _, netInterfaceAddress := range netInterfaceAddresses {
		networkIp, ok := netInterfaceAddress.(*net.IPNet)
		if ok && !networkIp.IP.IsLoopback() && networkIp.IP.To4() != nil {
			ip := networkIp.IP.String()
			return ip
		}
	}
	return ""
}

// NewFalse This only exists because the Vault client API is stupid.
func NewFalse() *bool {
	b := false
	return &b
}
func SecondsUntil3AM() int64 {
	timeStr := ""
	localTZ, _ := time.LoadLocation("America/New_York")
	hour, _, _ := time.Now().Clock()
	if hour > 0 {
		//before midnight so add a day
		timeStr = time.Now().AddDate(0, 0, 1).Format("20060102") + " 03:00:00"
	} else {
		//after midnight so don't add a day
		timeStr = time.Now().Format("20060102") + " 03:00:00"
	}

	t, _ := time.ParseInLocation("20060102 15:04:05", timeStr, localTZ)
	return int64(time.Until(t).Seconds())
}
func AmIRunningInAK8SPod() bool {
	_, set := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	return set
}
