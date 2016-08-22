package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/emc-advanced-dev/pkg/errors"
	"github.com/emc-advanced-dev/unik/pkg/types"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"fmt"
)

const unik_image_info = "Unik-Image-Info"

var awsAccessKeyId, awsSecretAccessKey, awsRegion, awsBucket string
var userSizeLimitGB = 8

type RequestToValidate struct {
	Pass   string      `json:"pass"`
	Method string      `json:"method"`
	Path   string      `json:"path"`
	Query  url.Values  `json:"query"`
	Header http.Header `json:"headers"`
}

type ValidationResponse struct {
	Message     string `json:"message"`
	AccessKeyID string `json:"access_key_id"`
	Region      string `json:"region"`
	Bucket      string `json:"bucket"`
}

type RequestToSign struct {
	RequestToValidate  RequestToValidate `json:"request_to_validate"`
	FormattedShortTime string            `json:"formatted_short_time"`
	ServiceName        string            `json:"service_name"`
	StringToSign       string            `json:"string_to_sign"`
}

type SignatureResponse struct {
	Signature []byte `json:"signature"`
	Err       string `json:"err"`
}

func main() {
	// Check if the s3 environment variables have been provided
	awsAccessKeyId = os.Getenv("AWS_ACCESS_KEY_ID")
	if awsAccessKeyId == "" {
		log.Fatal("AWS_ACCESS_KEY_ID environment variable must be provided")
	}
	awsSecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	if awsSecretAccessKey == "" {
		log.Fatal("AWS_SECRET_ACCESS_KEY environment variable must be provided")
	}
	awsRegion = os.Getenv("AWS_REGION")
	if awsRegion == "" {
		log.Fatal("AWS_REGION environment variable must be provided")
	}
	awsBucket = os.Getenv("AWS_BUCKET")
	if awsRegion == "" {
		log.Fatal("AWS_BUCKET environment variable must be provided")
	}
	svc := s3.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))
	r := gin.Default()

	// Validate the request sent by the UnikHubClient
	r.GET("/aws_info", func(c *gin.Context) {
		validationResponse := ValidationResponse{
			AccessKeyID: awsAccessKeyId,
			Region:      awsRegion,
			Bucket:      awsBucket,
		}

		c.JSON(200, validationResponse)
	})
	// Sign the request sent for the UnikHubClient
	r.POST("/sign", func(c *gin.Context) {
		// Exctract the information sent by the UnikHubClient
		req := c.Request
		decoder := json.NewDecoder(req.Body)
		var requestToSign RequestToSign
		err := decoder.Decode(&requestToSign)
		if err != nil {
			c.Error(err)
			return
		}
		if err := validate(svc, requestToSign.RequestToValidate); err != nil {
			c.JSON(401, SignatureResponse{
				Err: err.Error(),
			})
		}
		date := makeHmac([]byte("AWS4"+awsSecretAccessKey), []byte(requestToSign.FormattedShortTime))
		region := makeHmac(date, []byte(awsRegion))
		service := makeHmac(region, []byte(requestToSign.ServiceName))
		credentials := makeHmac(service, []byte("aws4_request"))
		signature := makeHmac(credentials, []byte(requestToSign.StringToSign))
		awsCredentials := SignatureResponse{
			Signature: signature,
		}
		c.JSON(200, awsCredentials)
	})
	r.GET("/images", func(c *gin.Context) {
		images, err := listS3images(awsBucket)
		if err != nil {
			c.Error(err)
			return
		}
		log.Printf("returned images: %v", images)
		c.JSON(200, images)
	})
	r.DELETE("/delete_image", func(c *gin.Context) {
		body, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Error(err)
			return
		}
		var creds struct {
			Username string `json:"user"`
			Password string `json:"pass"`
			Key      string `json:"key"`
		}
		if err := json.Unmarshal(body, &creds); err != nil {
			c.Error(err)
			return
		}
		key := creds.Key
		username := creds.Username
		password := creds.Password

		//validate user credentials first
		// If the access is private, check if the password provided it the correct one
		if password == "" {
			c.JSON(401, ValidationResponse{
				Message: "Password must be provided to delete an image",
			})
			return
		}
		headParams := &s3.HeadObjectInput{
			Bucket: aws.String(awsBucket),
			Key:    aws.String(key),
		}
		resp, headErr := svc.HeadObject(headParams)
		if headErr != nil {
			c.JSON(401, ValidationResponse{
				Message: "Can't retrieve information about the object " + key + ": " + err.Error(),
			})
			return
		}
		if username != *resp.Metadata["Unik-Email"] {
			c.JSON(401, ValidationResponse{
				Message: "Can't object belongs to user " + *resp.Metadata["Unik-Email"] + ", you gave me " + username,
			})
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(*resp.Metadata["Unik-Password"]), []byte(password))
		if err != nil {
			c.JSON(401, ValidationResponse{
				Message: "Wrong password provided: " + err.Error(),
			})
			return
		}

		params := &s3.DeleteObjectInput{
			Bucket: aws.String(awsBucket),
			Key:    aws.String(creds.Key),
		}
		result, err := s3.New(session.New(&aws.Config{Region: aws.String(awsRegion)})).DeleteObject(params)
		if err != nil {
			c.Error(errors.New("deleting image on s3 backend", err))
			return
		}
		c.String(204, result.String())
	})
	r.Run(":80")
}

func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func listS3images(bucketName string) ([]*types.UserImage, error) {
	s3svc := s3.New(session.New(&aws.Config{
		Region: aws.String(awsRegion),
	}))
	params := &s3.ListObjectsInput{
		Bucket: aws.String(bucketName),
	}
	//each object is an image
	output, err := s3svc.ListObjects(params)
	if err != nil {
		return nil, err
	}
	images := []*types.UserImage{}
	for _, obj := range output.Contents {
		params := &s3.HeadObjectInput{
			Bucket: aws.String(bucketName),
			Key:    obj.Key,
		}
		output, err := s3svc.HeadObject(params)
		if err != nil {
			return nil, err
		}
		//get metadata for each object
		//metadata represents the json-serialized Image metadata
		user := output.Metadata["unik-email"]
		if user == nil {
			continue
		}
		metadata := output.Metadata[unik_image_info]
		if metadata == nil {
			continue
		}
		log.Printf("metadata: %v", *metadata)
		var image types.Image
		if err := json.Unmarshal([]byte(*metadata), &image); err != nil {
			return nil, err
		}
		images = append(images, &types.UserImage{
			Image: &image,
			User:  *user,
		})
	}
	return images, nil
}

func validate(svc *s3.S3, requestToValidate RequestToValidate) (err error) {
	method := requestToValidate.Method
	path := requestToValidate.Path
	password := requestToValidate.Pass
	access := requestToValidate.Header.Get("X-Amz-Meta-Unik-Access")
	email := requestToValidate.Header.Get("X-Amz-Meta-Unik-Email")
	pathArray := strings.Split(path, "/")
	// Check that the path sent by the UnikHubClient is following the format /bucket/user/image/version
	if len(pathArray) != 4 {
		return errors.New("Invalid path provided by the UnikHubClient: "+path, nil)
	}
	user := strings.Split(path, "/")[1]
	image := strings.Split(path, "/")[2]
	version := strings.Split(path, "/")[3]

	//log.Printf("VALIDATING REQUEST:\nmethod: %v\npath: %v\nemail: %v\npassword: %v\naccess: %v\nuser: %v\nimage: %v\nversion: %v", method, path, email, password, access, user, image, version)

	// If this is a UnikHubClient push request (and not a part or the completion of a multipart upload)
	if (method == "POST" && requestToValidate.Query.Get("uploadId") == "") || (method == "PUT" && requestToValidate.Query.Get("partNumber") == "") {
		// Validate that the UnikHubClient has sent the required user metadata
		if password == "" || email == "" || access == "" {
			return errors.New("The UnikHubClient must provide the X-Amz-Meta-Unik-Password, X-Amz-Meta-Unik-Email and X-Amz-Meta-Unik-Access headers with any push request and the values can't be null", nil)
		}
		if access != "public" && access != "private" {
			return errors.New("The value of the X-Amz-Meta-Unik-Access headers must be public or private", nil)
		}
		// Send a Head request for the object user
		params := &s3.HeadObjectInput{
			Bucket: aws.String(awsBucket),
			Key:    aws.String(user),
		}
		resp, headErr := svc.HeadObject(params)
		if headErr != nil {
			// If the object user doesn't exist, this is the first push request executed by this user
			// The object user must be created
			// Hashing the password with the default cost of 10
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return errors.New("Can't generate the hash based on the password provided for the user: "+err.Error(), nil)
			}
			if strings.Contains(headErr.Error(), "status code: 404") {
				params := &s3.PutObjectInput{
					Bucket: aws.String(awsBucket),
					Key:    aws.String(user),
					Metadata: map[string]*string{
						"unik-password": aws.String(string(hashedPassword)),
						"unik-email":    aws.String(email),
						"unik-access":   aws.String(access),
					},
				}
				_, err := svc.PutObject(params)
				if err != nil {
					return errors.New("Can't create the object "+user+": "+err.Error(), nil)
				}
			} else {
				return errors.New("Can't check the user credentials: "+err.Error(), nil)
			}
			// If the object user exists, check if the password provided it the correct one
		} else {
			err = bcrypt.CompareHashAndPassword([]byte(*resp.Metadata["Unik-Password"]), []byte(password))
			if err != nil {
				return errors.New("Wrong password provided: "+err.Error(), nil)
			}
		}

		images, err := listS3images(awsBucket)
		if err != nil {
			return err
		}

		userSizeTotal := 0

		//unique names check
		for _, image := range images {
			if image.Name == image {
				return errors.New("image names must be unique, "+image+" is taken", err)
			}
			if image.User == user {
				userSizeTotal += image.SizeMb
			}
		}

		//available space check
		if sizeLimit := os.Getenv("MAX_SIZE"); sizeLimit != "" {
			userSizeLimitGB, err = strconv.Atoi(sizeLimit)
			if err != nil {
				return errors.New("invalid MAX_SIZE", err)
			}
		}

		userSizeLimitMB := userSizeLimitGB << 20
		if userSizeTotal >= userSizeLimitMB {
			return errors.New(fmt.Sprintf("user has reached size limit of %v mb", userSizeLimitMB), nil)
		}
	}

	// If this is a UnikHubClient pull request
	if method == "GET" {
		// Send a Head request for the object user
		params := &s3.HeadObjectInput{
			Bucket: aws.String(awsBucket),
			Key:    aws.String(user + "/" + image + "/" + version),
		}
		resp, headErr := svc.HeadObject(params)
		if headErr != nil {
			// If the error returned is different than 404, the object user/image/version can exist or not. Exiting
			if !strings.Contains(headErr.Error(), "status code: 404") {

				return errors.New("Can't retrieve information about the object "+user+"/"+image+"/"+version+": "+err.Error(), nil)
			}
			// If the object user/image/version exists, checking the if the access is public or private
		} else {
			// Checking if a correct access has been defined for the object
			if *resp.Metadata["Unik-Access"] != "public" && *resp.Metadata["Unik-Access"] != "private" {
				return errors.New("Incorrect access defined for the object "+user+"/"+image+"/"+version, nil)
			}
			// If the access is private, check if the password provided it the correct one
			if *resp.Metadata["Unik-Access"] == "private" {
				if password == "" {
					return errors.New("Password must be provided to access a private image", nil)
				}
				params := &s3.HeadObjectInput{
					Bucket: aws.String(awsBucket),
					Key:    aws.String(user),
				}
				resp, headErr := svc.HeadObject(params)
				if headErr != nil {
					return errors.New("Can't check the user credentials: "+err.Error(), nil)
				}
				err = bcrypt.CompareHashAndPassword([]byte(*resp.Metadata["Unik-Password"]), []byte(password))
				if err != nil {
					return errors.New("Wrong password provided: "+err.Error(), nil)
				}
			}
		}
	}

	return nil
}
