package model

import "time"

type User struct {
	GUID      string
	FirstName string
	LastName  string
	Email     string
}

type Token struct {
	UserGUID  string
	Hash      string
	CreatedAt time.Time
}
