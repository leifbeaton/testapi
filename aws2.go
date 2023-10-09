package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"fmt"
	"math/rand"
	"context"
	"io/ioutil"
	//"sort"
	"strings"
	"database/sql"
	//"crypto/rsa"
	//"crypto/x509"
	//"encoding/pem"
	//"encoding/base64"
	"net/mail"
	"sync"
	"errors"
	"time"

    "github.com/joho/godotenv"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/credentials"
    "github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/sts"
	//"github.com/aws/aws-sdk-go/service/iam"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"

    "github.com/gorilla/websocket"
)


var globaldebug = true
//var globalSession *session.Session
var userSessions = make(map[string]*session.Session)
var sessionsMutex = &sync.Mutex{}
var userSessionInitialized bool = false

var globalSessionEmail = "deploymentmanager@nginx"

var jwtKey = []byte("my_secret_key") // Changed by code or environment
var sessionTokens map[string]*session.Session = make(map[string]*session.Session)

var vpcID = ""

var instanceStatuses = make(map[string]string)




func init() {
    /*
	var err error
    globalSession, err = session.NewSession(&aws.Config{
        Region: aws.String("eu-central-2"), // replace with your default region
    })
    if err != nil {
        log.Fatalf("Failed to create session: %v", err)
    }
	*/
}




func logwrite(debug bool, msg string) {
	if debug {
		fmt.Println(msg)
	}
}



func main() {
	debug := globaldebug
	// Set up environment
	err := godotenv.Load("../.env")
	if err != nil {
			log.Fatalf("An error occured. Err: %s", err)
	}
	envjwtkey, ok := os.LookupEnv("JWTKEY")
	if !ok {
			envjwtkey = RandStringRunes(50)
			f, err := os.OpenFile("../.env",
					os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
					log.Println(err)
			}
			if _, err := f.WriteString("\nJWTKEY=" + envjwtkey); err != nil {
					log.Println(err)
			}
			f.Close()
	}
	jwtKey = []byte(envjwtkey)
	logwrite(debug, "JWT Key:" + envjwtkey)

	http.HandleFunc("/api/aws/gettokenemail", handleGetTokenEmail)

	// Create AWS elements
	//http.HandleFunc("/api/aws/createvirtualprivatecloud", handleCreateVPC)


	// Delete AWS elements
	//http.HandleFunc("/api/aws/deletevirtualprivatecloud", handleDeleteVPC)



	// Get AWS elements
	http.HandleFunc("/api/aws/listvpcs", handleListVPCs)
	//http.HandleFunc("/api/aws/getvpc", getVPCInfo)



	//http.HandleFunc("/api/aws/getemailaddress", handleGetEmailAddressIAM)
	//http.HandleFunc("/api/aws/getregionlistfull", handleGetRegionListFull)
	http.HandleFunc("/api/aws/getregionlist", handleGetRegionList)
	http.HandleFunc("/api/aws/createsession", handleCreateSession)
	//http.HandleFunc("/api/aws/getsessiontoken", handleGetSessionToken)
	http.HandleFunc("/api/aws/hassession", handleCheckSession)
	http.HandleFunc("/api/aws/getavailabilityzones", handleGetAvailabilityZones)
	http.HandleFunc("/api/aws/getlinuximages", handleGetLinuxImages)
	http.HandleFunc("/api/aws/getinstancetypes", handleGetInstanceTypes)

	//http.HandleFunc("/api/aws/createinstance", handleCreateInstance)
	//http.HandleFunc("/api/aws/getinstancestatus", handleGetInstanceStatus)
	//http.HandleFunc("/api/aws/getinstancedetails", handleGetInstanceDetails)
	//http.HandleFunc("/api/aws/setinstancetags", handleSetInstanceTags)
	//http.HandleFunc("/api/aws/createnetwork", handleCreateNetwork)

    http.HandleFunc("/api/aws/websocket", handleWebsockets)

	log.Fatal(http.ListenAndServe(":10080", nil))

	//go startInstanceTerminator()
}



func RandStringRunes(n int) string {
	letterRunes := []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
var (
    lowerCharSet   = "abcdedfghijklmnopqrst"
    upperCharSet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    specialCharSet = "!@#$%&*"
    numberSet      = "0123456789"
    allCharSet     = lowerCharSet + upperCharSet + specialCharSet + numberSet
)
func generatePassword(passwordLength, minSpecialChar, minNum, minUpperCase int) string {
    var password strings.Builder

    //Set special character
    for i := 0; i < minSpecialChar; i++ {
        random := rand.Intn(len(specialCharSet))
        password.WriteString(string(specialCharSet[random]))
    }

    //Set numeric
    for i := 0; i < minNum; i++ {
        random := rand.Intn(len(numberSet))
        password.WriteString(string(numberSet[random]))
    }

    //Set uppercase
    for i := 0; i < minUpperCase; i++ {
        random := rand.Intn(len(upperCharSet))
        password.WriteString(string(upperCharSet[random]))
    }

    remainingLength := passwordLength - minSpecialChar - minNum - minUpperCase
    for i := 0; i < remainingLength; i++ {
        random := rand.Intn(len(allCharSet))
        password.WriteString(string(allCharSet[random]))
    }
    inRune := []rune(password.String())
	rand.Shuffle(len(inRune), func(i, j int) {
		inRune[i], inRune[j] = inRune[j], inRune[i]
	})
	return string(inRune)
}
func getDBConn() (*sql.DB, error) {
	connString := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s", os.Getenv("PSQLUSER"), os.Getenv("PSQLPASS"), os.Getenv("PSQLHOST"), os.Getenv("PSQLDB"), os.Getenv("PSQLSSLMODE"))
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, err
	}

	return db, nil
}



// Error handling
func handleError(w http.ResponseWriter, error string, code int) {
    http.Error(w, error, code)
}
// Success response handling
func handleSuccess(w http.ResponseWriter, response interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}


var clients = make(map[*WebsocketsClient]bool) // connected clients
var broadcast = make(chan []byte)    // broadcast channel
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true
    },
}
func handleWebsockets(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()

    client := &Client{conn: conn, send: make(chan []byte)}
    clients[client] = true

    go func() {
        defer delete(clients, client)
        for {
            _, _, err := client.conn.ReadMessage()
            if err != nil {
                break
            }
        }
    }()

    for {
        select {
        case message, ok := <-client.send:
            if !ok {
                return
            }
            client.conn.WriteMessage(websocket.TextMessage, message)
        }
    }
}

func getTokenEmail(w http.ResponseWriter, r *http.Request) string {
	// Check the Authorization header for a JWT token
	//authHeader := r.Header.Get("Authorization")
	accessToken, err := r.Cookie("accessToken")
	if err != nil {
		handleError(w, "Access token bad or missing - " + err.Error(), http.StatusBadRequest)
        return ""
	}

	// Parse the JWT token
	tokenString := strings.Replace(accessToken.Value, "Bearer ", "", 1)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the token signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			log.Printf("tokenString: %s", tokenString)
			return jwtKey, nil
	})
	if err != nil {
		handleError(w, "Unauthorized - " + err.Error(), http.StatusUnauthorized)
        return ""
	}

	// Check if the token is valid and not expired
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email := claims["Email"].(string)
		log.Printf("Email: %s", email)
        return email
	}

	return "Invalid token"
}
func handleGetTokenEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		handleError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"email": getTokenEmail(w, r)})
}
func isEmail(email string) bool {
    _, err := mail.ParseAddress(email)
    return err == nil
}





// Check if an existing AWS session is valid
func isSessionValid(sess *session.Session) bool {
    if sess == nil {
        return false
    }
    stsSvc := sts.New(sess)
    ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
    defer cancel()
    _, err := stsSvc.GetCallerIdentityWithContext(ctx, &sts.GetCallerIdentityInput{})
    return err == nil
}
func getUserSession(email string, creds *AWSCredentials) (*session.Session, error) {
    sessionsMutex.Lock()
    defer sessionsMutex.Unlock()

    if existingSession, ok := userSessions[email]; ok && isSessionValid(existingSession) {
        return existingSession, nil
    }

    // Clear invalid session if exists
    //if ok {
    //    delete(userSessions, email)
    //}

    // If no session exists and no credentials were provided, return an error
    if creds == nil {
        return nil, errors.New("No session exists for this user and no credentials provided")
    }

    // Create a new session for the user
    newSession, err := session.NewSession(&aws.Config{
        Region: aws.String("eu-west-2"), // or any other region
        Credentials: credentials.NewStaticCredentials(creds.AWSAccessKeyId, creds.AWSSecretAccessKey, creds.AWSSessionToken),
    })

    if err != nil {
        return nil, err
    }

    // Store the new session
    userSessions[email] = newSession

    // Check if a user session has been initialized
    if !userSessionInitialized {
        // Create a duplicate session for "deploymentmanager@nginx"
        userSessions[globalSessionEmail] = newSession.Copy()
        userSessionInitialized = true
    }

	svc := ec2.New(newSession)

    result, err := svc.DescribeVpcs(nil)
    if err != nil {
        fmt.Println("Error describing VPCs.", err)
        return nil, err
    }

    if len(result.Vpcs) == 0 {
        fmt.Println("No VPCs found in this region.")
        return nil, err
    }

    vpcID = aws.StringValue(result.Vpcs[0].VpcId)
    log.Printf("VPC ID: %s\n", vpcID)

    return newSession, nil
}
func handleCreateSession(w http.ResponseWriter, r *http.Request) {
    debug := globaldebug
    logwrite(debug, "Handling GetSession...")
    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        handleError(w, "Error reading request body: " + err.Error(), http.StatusBadRequest)
        return
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    logwrite(debug, "Request body: %s\n" + string(body))

    var creds AWSCredentials
    err = json.Unmarshal(body, &creds)
    if err != nil {
        handleError(w, fmt.Sprintf("Error decoding JSON: %s", err.Error()), http.StatusBadRequest)
        return
    }

    email := getTokenEmail(w, r)
    if !isEmail(email) {
        handleError(w, "Invalid email in token", http.StatusBadRequest)
        return
    }

    userSession, err := getUserSession(email, &creds)
    if err != nil {
        handleError(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Make a dummy call to validate the session
    stsSvc := sts.New(userSession)
    _, err = stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
    if err != nil {
        // If the call failed, return an unauthorized status
        handleError(w, err.Error(), http.StatusUnauthorized)
        return
    }

    userSessions[email] = userSession

	handleSuccess(w, map[string]bool{"success": true})
}


func handleCheckSession(w http.ResponseWriter, r *http.Request) {
    email := getTokenEmail(w, r)
    if !isEmail(email) {
        handleError(w, "Invalid email in token", http.StatusBadRequest)
        return
    }

    sessionsMutex.Lock()
    defer sessionsMutex.Unlock()

    existingSession, ok := userSessions[email]
    if !ok {
        handleSuccess(w, map[string]bool{"valid": false})
        return
    }

    if isSessionValid(existingSession) {
        handleSuccess(w, map[string]bool{"valid": true})
        return
    }

    handleSuccess(w, map[string]bool{"valid": false})
}




func handleGetRegionList(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        handleError(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    email := getTokenEmail(w, r)
    if !isEmail(email) {
        handleError(w, "Invalid email in token", http.StatusBadRequest)
        return
    }

    sessionsMutex.Lock()
    userSession, ok := userSessions[email]
    sessionsMutex.Unlock()

    if !ok || !isSessionValid(userSession) {
        handleError(w, "No valid session exists for this user", http.StatusUnauthorized)
        return
    }

    svc := ec2.New(userSession)
    input := &ec2.DescribeRegionsInput{}
    result, err := svc.DescribeRegions(input)
    if err != nil {
        handleError(w, err.Error(), http.StatusInternalServerError)
        return
    }

    regions := make(map[string]string)
    for _, region := range result.Regions {
        regions[*region.RegionName] = *region.Endpoint
    }

    handleSuccess(w, map[string]interface{}{
        "Regions": regions,
    })
}
func handleGetAvailabilityZones(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        handleError(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

	var inputData struct {
        Region string `json:"region"`
    }

	decoder := json.NewDecoder(r.Body)
    err := decoder.Decode(&inputData)
    if err != nil {
        handleError(w, "Error decoding JSON: "+err.Error(), http.StatusBadRequest)
        return
    }

    if inputData.Region == "" {
        handleError(w, "Region must be specified", http.StatusBadRequest)
        return
    }

    email := getTokenEmail(w, r)
    if !isEmail(email) {
        handleError(w, "Invalid email in token", http.StatusBadRequest)
        return
    }

    sessionsMutex.Lock()
    userSession, ok := userSessions[email]
    sessionsMutex.Unlock()

    if !ok || !isSessionValid(userSession) {
        handleError(w, "No valid session exists for this user", http.StatusUnauthorized)
        return
    }

    svc := ec2.New(userSession, aws.NewConfig().WithRegion(inputData.Region))
    input := &ec2.DescribeAvailabilityZonesInput{}
    result, err := svc.DescribeAvailabilityZones(input)
    if err != nil {
        handleError(w, err.Error(), http.StatusInternalServerError)
        return
    }

    zones := make([]string, len(result.AvailabilityZones))
    for i, zone := range result.AvailabilityZones {
        zones[i] = *zone.ZoneName
    }

    handleSuccess(w, map[string]interface{}{
        "AvailabilityZones": zones,
    })
}
func handleGetLinuxImages(w http.ResponseWriter, r *http.Request) {
    email := getTokenEmail(w, r)
    if !isEmail(email) {
        handleError(w, "Invalid email in token", http.StatusBadRequest)
        return
    }

    sessionsMutex.Lock()
    userSession, ok := userSessions[email]
    sessionsMutex.Unlock()

    if !ok || !isSessionValid(userSession) {
        handleError(w, "No valid session exists for this user", http.StatusUnauthorized)
        return
    }

    // Read the request body
    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        handleError(w, "Error reading request body: "+err.Error(), http.StatusBadRequest)
        return
    }

    var input GetAWSImagesInput
    err = json.Unmarshal(body, &input)
    if err != nil {
        handleError(w, "Error decoding JSON: "+err.Error(), http.StatusBadRequest)
        return
    }

    // Validate region
    if input.Region == "" {
        handleError(w, "Region is required", http.StatusBadRequest)
        return
    }

    // Set defaults if not provided
    if len(input.Owners) == 0 {
        input.Owners = []string{"amazon"}
    }

    if len(input.Filters) == 0 {
        input.Filters = []string{"*linux*"}
    }

    // Create filters
    filters := []*ec2.Filter{
        {
            Name:   aws.String("name"),
            Values: aws.StringSlice(input.Filters),
        },
    }

    svc := ec2.New(userSession, &aws.Config{Region: aws.String(input.Region)})
    awsInput := &ec2.DescribeImagesInput{
        Filters: filters,
        Owners:  aws.StringSlice(input.Owners),
    }

    result, err := svc.DescribeImages(awsInput)
    if err != nil {
        handleError(w, "Failed to describe images: "+err.Error(), http.StatusInternalServerError)
        return
    }

    images := []map[string]string{}
    for _, image := range result.Images {
        images = append(images, map[string]string{
            "ImageId": *image.ImageId,
            "Name":    *image.Name,
        })
    }

    handleSuccess(w, images)
}
func handleGetInstanceTypes(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        handleError(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    var input struct {
        Region string `json:"region"`
    }

    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&input); err != nil {
        handleError(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if input.Region == "" {
        handleError(w, "Region is required", http.StatusBadRequest)
        return
    }

    email := getTokenEmail(w, r)
    if !isEmail(email) {
        handleError(w, "Invalid email in token", http.StatusBadRequest)
        return
    }

    sessionsMutex.Lock()
    userSession, ok := userSessions[email]
    sessionsMutex.Unlock()

    if !ok || !isSessionValid(userSession) {
        handleError(w, "No valid session exists for this user", http.StatusUnauthorized)
        return
    }

    svc := ec2.New(userSession, &aws.Config{Region: aws.String(input.Region)})

    // Create a slice to hold the instance types
    var instanceTypes []map[string]interface{}

    // Call DescribeInstanceTypes
    err := svc.DescribeInstanceTypesPages(&ec2.DescribeInstanceTypesInput{},
        func(page *ec2.DescribeInstanceTypesOutput, lastPage bool) bool {
            for _, instanceType := range page.InstanceTypes {
                instanceTypes = append(instanceTypes, map[string]interface{}{
                    "InstanceType":       aws.StringValue(instanceType.InstanceType),
                    "VCpuInfo":           instanceType.VCpuInfo,
                    "MemoryInfo":         instanceType.MemoryInfo,
                    "CurrentGeneration":  aws.BoolValue(instanceType.CurrentGeneration),
                    "NetworkPerformance": aws.StringValue(instanceType.NetworkInfo.NetworkPerformance),
                })
            }
            return !lastPage
        })
    if err != nil {
        handleError(w, fmt.Sprintf("Failed to describe instance types: %s", err), http.StatusInternalServerError)
        return
    }

    handleSuccess(w, instanceTypes)
}



// handleListVPCs lists available VPCs with tags.
func handleListVPCs(w http.ResponseWriter, r *http.Request) {
    // Validate method type
    if r.Method != http.MethodGet {
        handleError(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    // Retrieve the email from token.
    email := getTokenEmail(w, r)
    if !isEmail(email) {
        handleError(w, "Invalid email in token", http.StatusBadRequest)
        return
    }

    // Lock to safely read the userSessions map.
    sessionsMutex.Lock()
    userSession, ok := userSessions[email]
    sessionsMutex.Unlock()
    
    if !ok || userSession == nil {
        handleError(w, "No session exists for this user", http.StatusUnauthorized)
        return
    }

    // Create EC2 service client
    svc := ec2.New(userSession)

    // Describe VPCs
    result, err := svc.DescribeVpcs(nil)
    if err != nil {
        handleError(w, fmt.Sprintf("Error describing VPCs: %s", err.Error()), http.StatusInternalServerError)
        return
    }

    var vpcsWithTags []VPCWithTag
    for _, vpc := range result.Vpcs {
        tags := make(map[string]string)
        for _, tag := range vpc.Tags {
            tags[aws.StringValue(tag.Key)] = aws.StringValue(tag.Value)
        }
        vpcsWithTags = append(vpcsWithTags, VPCWithTag{
            VPCID: aws.StringValue(vpc.VpcId),
            Tags:  tags,
        })
    }

    handleSuccess(w, vpcsWithTags)
}