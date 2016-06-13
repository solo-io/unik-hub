package main

import (
	"github.com/gin-gonic/gin"
	"github.com/emc-advanced-dev/unik/pkg/types"
	"io/ioutil"
	"os"
	"io"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pborman/uuid"
	"github.com/aws/aws-sdk-go/aws/session"
	"encoding/json"
)

func main(){
	startServer()
}

func startServer(){
	r := gin.Default()
	r.GET("/images", func(c *gin.Context) {
		images, err := listS3images("default-bucket")
		if err != nil {
			c.Error(err)
			return
		}
		c.JSON(200, images)
	})
	r.POST("/upload_image", func(c *gin.Context){
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
	r.Run() // listen and server on 0.0.0.0:8080
}

func listS3images(bucketName string) ([]*types.Image, error) {
	s3svc := s3.New(session.New(&aws.Config{
		Region: aws.String("us-east-1"),
	}))
	params := &s3.ListObjectsInput{
		Bucket:        aws.String(bucketName),
	}
	//each object is an image
	output, err := s3svc.ListObjects(params)
	if err != nil {
		return nil, err
	}
	images := make([]*types.Image, len(output.Contents))
	for _, obj := range output.Contents {
		params := &s3.GetObjectInput{
			Bucket:        aws.String(bucketName),
			Key: 	       obj.Key,
		}
		output, err := s3svc.GetObject(params)
		if err != nil {
			return nil, err
		}
		//get metadata for each object
		//metadata represents the json-serialized Image metadata
		metadata := output.Metadata["metadata"]
		var image *types.Image
		if err := json.Unmarshal([]byte(*metadata), image); err != nil {
			return nil, err
		}

		images = append(images, image)
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
		Region: aws.String("us-east-1"),
	}))
	if _, err := s3svc.PutObject(params); err != nil {
		return err
	}
	return nil
}