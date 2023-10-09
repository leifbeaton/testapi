package main

type WebsocketsClient struct {
    conn *websocket.Conn
    send chan []byte
}



type AWSCredentials struct {
	AWSAccessKeyId     	string `json:"access_key_id"`
	AWSSecretAccessKey 	string `json:"secret_access_key"`
	AWSSessionToken    	string `json:"aws_session_token"`
	Region             	string `json:"aws_region"`
}


type GetAWSImagesInput struct {
    Region  string   `json:"region"`
    Filters []string `json:"filters"`
    Owners  []string `json:"owners"`
}





// VPCWithTag represents a VPC along with its tags.
type VPCWithTag struct {
    VPCID string            `json:"vpcId"`
    Tags  map[string]string `json:"tags"`
}

