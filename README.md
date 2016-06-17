# unik-hub
code for UniK Hub backend

The UnikHub muist be started with the following environment variables:

- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_REGION
- AWS_BUCKET

The client can use s3manager to upload and download objects with multiple thread.

Import the following:

``
"github.com/djannot/aws-sdk-go/aws"
"github.com/djannot/aws-sdk-go/aws/session"
"github.com/djannot/aws-sdk-go/service/s3"
"github.com/djannot/aws-sdk-go/service/s3/s3manager"
```

Example to upload an object:

```
uploader := s3manager.NewUploader(session.New(&aws.Config{Region: aws.String("AWSREGION")}), func(d *s3manager.Uploader) {
  d.PartSize = 5 * 1024 * 1024 // 64MB per part
})
result, err := uploader.Upload(&s3manager.UploadInput{
    Body:   reader,
    Bucket: aws.String("AWSBUCKET"),
    Key:    aws.String("/user/image/version"),
    Metadata: map[string]*string{
      "unik-password": aws.String("password"),
      "unik-email": aws.String("firstname.lastname@company.com"),
      "unik-access": aws.String("private"),
    },
})
```

AWSREGION and AWSBUCKET will be replaced when the call will be intercept by https://github.com/djannot/aws-sdk-go

The unik-password and the unik-access (public or private) must be set for each upload.

The unik-email is only used during the first upload of the first image.

Example to upload an object:

```
downloader := s3manager.NewDownloader(session.New(&aws.Config{Region: aws.String("AWSREGION")}), func(d *s3manager.Downloader) {
  d.PartSize = 5 * 1024 * 1024 // 64MB per part
})

_, err = downloader.Download(file, &s3.GetObjectInput{
    Bucket: aws.String("AWSBUCKET"),
    Key: aws.String("/user/image/version"),
    Password: aws.String("password"),
})
```

AWSREGION and AWSBUCKET will be replaced when the call will be intercept by https://github.com/djannot/aws-sdk-go

The unik-password must be set when downloading a private image.
