package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/emc-advanced-dev/unik/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/pborman/uuid"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const unik_image_info = "Unik-Image-Info"

var awsAccessKeyId, awsSecretAccessKey, awsRegion, awsBucket string

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
	r.POST("/validate", func(c *gin.Context) {
		// Exctract the information sent by the UnikHubClient
		req := c.Request
		decoder := json.NewDecoder(req.Body)
		var requestToValidate RequestToValidate
		err := decoder.Decode(&requestToValidate)
		if err != nil {
			c.Error(err)
			return
		}
		method := requestToValidate.Method
		path := requestToValidate.Path
		password := requestToValidate.Header.Get("X-Amz-Meta-Unik-Password")
		email := requestToValidate.Header.Get("X-Amz-Meta-Unik-Email")
		access := requestToValidate.Header.Get("X-Amz-Meta-Unik-Access")
		pathArray := strings.Split(path, "/")
		// Check that the path sent by the UnikHubClient is following the format /bucket/user/image/version
		if len(pathArray) != 4 {
			c.JSON(401, ValidationResponse{
				Message: "Invalid path provided by the UnikHubClient: "+path,
			})
			return
		}
		user := strings.Split(path, "/")[1]
		image := strings.Split(path, "/")[2]
		version := strings.Split(path, "/")[3]

		// If this is a UnikHubClient push request (and not a part or the completion of a multipart upload)
		if (method == "POST" && requestToValidate.Query.Get("uploadId") == "") || (method == "PUT" && requestToValidate.Query.Get("partNumber") == "") {
			// Validate that the UnikHubClient has sent the required user metadata
			if password == "" || email == "" || access == "" {
				c.JSON(401, ValidationResponse{
					Message: "The UnikHubClient must provide the X-Amz-Meta-Unik-Password, X-Amz-Meta-Unik-Email and X-Amz-Meta-Unik-Access headers with any push request and the values can't be null",
				})
				return
			}
			if access != "public" && access != "private" {
				c.JSON(401, ValidationResponse{
					Message: "The value of the X-Amz-Meta-Unik-Access headers must be public or private",
				})
				return
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
					c.JSON(401, ValidationResponse{
						Message: "Can't generate the hash based on the password provided for the user: " + err.Error(),
					})
					return
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
						c.JSON(401, ValidationResponse{
							Message: "Can't create the object " + user + ": " + err.Error(),
						})
						return
					}
				} else {
					c.JSON(401, ValidationResponse{
						Message: "Can't check the user credentials: " + err.Error(),
					})
					return
				}
				// If the object user exists, check if the password provided it the correct one
			} else {
				err = bcrypt.CompareHashAndPassword([]byte(*resp.Metadata["Unik-Password"]), []byte(password))
				if err != nil {
					c.JSON(401, ValidationResponse{
						Message: "Wrong password provided: " + err.Error(),
					})
					return
				}
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
					c.JSON(401, ValidationResponse{
						Message: "Can't retrieve information about the object " + user + "/" + image + "/" + version + ": " + err.Error(),
					})
					return
				}
				// If the object user/image/version exists, checking the if the access is public or private
			} else {
				// Checking if a correct access has been defined for the object
				if *resp.Metadata["Unik-Access"] != "public" && *resp.Metadata["Unik-Access"] != "private" {
					c.JSON(401, ValidationResponse{
						Message: "Incorrect access defined for the object " + user + "/" + image + "/" + version,
					})
					return
				}
				// If the access is private, check if the password provided it the correct one
				if *resp.Metadata["Unik-Access"] == "private" {
					if password == "" {
						c.JSON(401, ValidationResponse{
							Message: "Password must be provided to access a private image",
						})
						return
					}
					params := &s3.HeadObjectInput{
						Bucket: aws.String(awsBucket),
						Key:    aws.String(user),
					}
					resp, headErr := svc.HeadObject(params)
					if headErr != nil {
						c.JSON(401, ValidationResponse{
							Message: "Can't check the user credentials: " + err.Error(),
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
				}
			}
		}

		validationResponse := ValidationResponse{
			AccessKeyID: awsAccessKeyId,
			Region:      awsRegion,
			Bucket:      awsBucket,
		}

		c.JSON(200, validationResponse)
	})
	// Sign the request sent for the UnikHubClient
	r.POST("/sign", func(c *gin.Context) {
		req := c.Request
		decoder := json.NewDecoder(req.Body)
		var requestToSign RequestToSign
		err := decoder.Decode(&requestToSign)
		if err != nil {
			c.Error(err)
			return
		}
		date := makeHmac([]byte("AWS4"+awsSecretAccessKey), []byte(requestToSign.FormattedShortTime))
		region := makeHmac(date, []byte(awsRegion))
		service := makeHmac(region, []byte(requestToSign.ServiceName))
		credentials := makeHmac(service, []byte("aws4_request"))
		signature := makeHmac(credentials, []byte(requestToSign.StringToSign))
		awsCredentials := AWSCredentials{
			AccessKeyID: awsAccessKeyId,
			Region:      awsRegion,
			Signature:   signature,
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
	r.POST("/upload_image", func(c *gin.Context) {
		req := c.Request
		//parse multipart form
		if err := req.ParseMultipartForm(0); err != nil {
			c.Error(err)
			return
		}
		//get file from request
		uploadedFile, _, err := req.FormFile("form_file_name")
		if err != nil {
			c.Error(err)
			return
		}
		//copy file to disk
		tmpFile, err := ioutil.TempFile("", "")
		if err != nil {
			c.Error(err)
			return
		}
		defer os.Remove(tmpFile.Name())
		if _, err := io.Copy(tmpFile, uploadedFile); err != nil {
			c.Error(err)
			return
		}

		//get metadata from request
		//metadata represents the json-serialized Image metadata
		metadata := req.FormValue("metadata")

		//upload file to s3
		if err := uploadFileS3("default-bucket", tmpFile, metadata); err != nil {
			c.Error(err)
			return
		}

		c.JSON(201, "Image Created")
	})
	r.Run(":80")
}

type RequestToValidate struct {
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
	FormattedShortTime string `json:"formatted_short_time"`
	ServiceName        string `json:"service_name"`
	StringToSign       string `json:"string_to_sign"`
}

type AWSCredentials struct {
	AccessKeyID string `json:"access_key_id"`
	Region      string `json:"region"`
	Signature   []byte `json:"signature"`
}

func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func listS3images(bucketName string) ([]*types.Image, error) {
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
	images := []*types.Image{}
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
		metadata := output.Metadata[unik_image_info]
		if metadata == nil {
			continue
		}
		log.Printf("metadata: %v", *metadata)
		var image types.Image
		if err := json.Unmarshal([]byte(*metadata), &image); err != nil {
			return nil, err
		}
		images = append(images, &image)
	}
	return images, nil
}

func uploadFileS3(bucketName string, file *os.File, metadata string) error {
	fi, err := file.Stat()
	if err != nil {
		return err
	}
	uuid := uuid.New()
	size := fi.Size()
	params := &s3.PutObjectInput{
		Bucket:        aws.String(bucketName),
		Key:           aws.String(uuid),
		Metadata:      map[string]*string{"metadata": aws.String(metadata)},
		ACL:           aws.String("private"),
		Body:          file,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String("application/octet-stream"),
	}
	s3svc := s3.New(session.New(&aws.Config{
		Region: aws.String(awsRegion),
	}))
	if _, err := s3svc.PutObject(params); err != nil {
		return err
	}
	return nil
}
