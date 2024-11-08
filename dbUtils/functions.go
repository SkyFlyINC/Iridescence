package dbUtils

import (
	"config"
	"database/sql"
	"encoding/json"
	"fmt"
	jsonprovider "jsonProvider"
	"logger"
	"time"
)

func SaveUserToDB(username, hashedPassword string, salt []byte) (int64, error) {
	UseDB(db, _BasicChatDBName)
	query := "INSERT INTO userdatatable (userName, userPasswordHashValue, passwordSalt, userAvatar, userFriendList, userGroupList, userHomePageData, userNote, userPermission, userSettings) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	result, err := db.Exec(query, username, hashedPassword, salt, confData.UserSettings.DefaultAvatar, jsonprovider.StringifyJSON(confData.UserSettings.DefaultFriendList), jsonprovider.StringifyJSON(confData.UserSettings.DefaultGroupList), jsonprovider.StringifyJSON(confData.UserSettings.DefaultHomePageData), confData.UserSettings.DefaultNote, config.PermissionOrdinaryUser, jsonprovider.StringifyJSON(confData.UserSettings.DefaultSettings))
	if err != nil {
		return 0, err
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return userID, nil
}

// 消息的两种基本状态
const (
	Unread = iota
	Read
)

// 群消息的自定义状态
type ExtraDataForGroupMessage struct {
	State     int             `json:"state"`
	ExtraJSON json.RawMessage `json:"extraJSON"`
}

func SaveMessageToDB(userID int, recipientID int, messageContent json.RawMessage, messageType int) (int, error) {
	insertQuery := "INSERT INTO messages (senderID,receiverID,messageBody,time,messageType,state) VALUES (?,?,?,?,?,?)"
	timestamp := time.Now().UnixNano() //纳秒事件戳
	result, err := db.Exec(insertQuery, userID, recipientID, messageContent, timestamp, messageType, Unread)
	if err != nil {
		logger.Error("保存用户消息时出现错误", err)
		return 0, err
	}

	messageID, err := result.LastInsertId()
	if err != nil {
		logger.Error("获取插入消息的ID时出现错误", err)
		return 0, err
	}

	return int(messageID), nil
}

func SaveGroupMessageToDB(userID int, recipientID int, messageContent string, messageType int) (int, error) {
	insertQuery := "INSERT INTO groupmessages (senderID,receiverID,messageBody,time,messageType,extra) VALUES (?,?,?,?,?,?)"
	timestamp := time.Now().UnixNano() //纳秒事件戳
	result, err := db.Exec(insertQuery, userID, recipientID, messageContent, timestamp, messageType, ExtraDataForGroupMessage{
		State: Unread,
	})
	if err != nil {
		logger.Error("保存用户消息时出现错误", err)
		return 0, err
	}

	messageID, err := result.LastInsertId()
	if err != nil {
		logger.Error("获取插入消息的ID时出现错误", err)
		return 0, err
	}

	return int(messageID), nil
}

// SaveOfflineMessageToDB 返回messageID
func SaveOfflineMessageToDB(messageID int, userID int, recipientID int, messageContent json.RawMessage, messageType int) (int, error) {
	insertQuery := "INSERT INTO offlinemessages (messageID ,senderID,receiverID,messageBody,time,messageType) VALUES (?,?,?,?,?,?)"
	timestamp := time.Now().UnixNano() //纳秒事件戳
	result, err := db.Exec(insertQuery, messageID, userID, recipientID, messageContent, timestamp, messageType)
	if err != nil {
		logger.Error("保存用户离线消息时出现错误", err)
		return 0, err
	}

	offlineMessageID, err := result.LastInsertId()
	if err != nil {
		logger.Error("获取插入消息的ID时出现错误", err)
		return 0, err
	}

	return int(offlineMessageID), nil
}
func SaveOfflineGroupMessageToDB(groupMessageID int, userID int, recipientID int, messageContent string, messageType int) (int, error) {
	insertQuery := "INSERT INTO offlinegroupmessages (groupMessageID,senderID,receiverID,messageBody,time,messageType) VALUES (?,?,?,?,?,?)"
	timestamp := time.Now().UnixNano() //纳秒事件戳
	result, err := db.Exec(insertQuery, groupMessageID, userID, recipientID, messageContent, timestamp, messageType)
	if err != nil {
		logger.Error("保存群聊离线消息时出现错误", err)
		return 0, err
	}

	offlineGroupMessageID, err := result.LastInsertId()
	if err != nil {
		logger.Error("获取群聊插入消息的ID时出现错误", err)
		return 0, err
	}

	return int(offlineGroupMessageID), nil
}

func GetDBPasswordHash(userID int) (string, []byte, error) {
	UseDB(db, _BasicChatDBName)
	query := "SELECT userPasswordHashValue, passwordSalt FROM userdatatable WHERE userID = ?"
	row := db.QueryRow(query, userID)

	var passwordHash string
	var salt []byte
	err := row.Scan(&passwordHash, &salt)
	if err != nil {
		if err == sql.ErrNoRows {
			// 用户不存在
			return "", nil, fmt.Errorf("找不到用户")
		}
		// 处理其他查询错误
		return "", nil, err
	}

	return passwordHash, salt, nil
}
func GetUserFromDB(userID int) (*jsonprovider.GetUserDataResponse, error) {
	// 从数据库中获取用户信息
	var username, userAvatar, userNote string
	var userPermission uint
	var userFriendList json.RawMessage
	err := db.QueryRow("SELECT userName, userAvatar, userNote, userPermission, userFriendList FROM basic_chat_base.userdatatable WHERE userID = ?", userID).Scan(&username, &userAvatar, &userNote, &userPermission, &userFriendList)
	if err != nil {
		logger.Error("获取用户数据失败:", err)
		return nil, err
	}

	// 创建 User 结构体
	user := &jsonprovider.GetUserDataResponse{
		UserID:         userID,
		UserName:       username,
		UserAvatar:     userAvatar,
		UserNote:       userNote,
		UserPermission: userPermission,
		UserFriendList: userFriendList,
	}

	return user, nil
}
func SavePostToDB(userID int, content string) error {
	// 获取当前时间
	postTime := time.Now().Unix()

	// 插入新的帖子到数据库
	_, err := db.Exec("INSERT INTO basic_chat_base.userposts (authorId, content, time) VALUES (?, ?, ?)", userID, content, postTime)
	if err != nil {
		logger.Error("Failed to save post to DB:", err)
		return err
	}

	return nil
}

func GetPostFromDB(postID int64) (jsonprovider.GetPostResponse, error) {
	var post jsonprovider.GetPostResponse

	// 从数据库中获取帖子
	err := db.QueryRow("SELECT authorId, postId, content, time, comments FROM userposts WHERE postId = ?", postID).Scan(&post.AuthorID, &post.PostID, &post.Content, &post.Time, &post.Comments)
	if err != nil {
		logger.Error("Failed to get post from DB:", err)
		return post, err
	}

	return post, nil
}
func GetUserPostsFromDB(userID int, startTime, endTime int64) ([]jsonprovider.GetPostResponse, error) {
	// 从数据库中获取帖子
	rows, err := db.Query("SELECT authorId, postId, content, time, comments FROM userposts WHERE authorId = ? AND time BETWEEN ? AND ?", userID, startTime, endTime)
	if err != nil {
		logger.Error("Failed to get posts from DB:", err)
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			logger.Error("SQL错误", err)
		}
	}(rows)

	// 读取帖子
	var posts []jsonprovider.GetPostResponse
	for rows.Next() {
		var post jsonprovider.GetPostResponse
		err := rows.Scan(&post.AuthorID, &post.PostID, &post.Content, &post.Time, &post.Comments)
		if err != nil {
			logger.Error("Failed to read post:", err)
			return nil, err
		}
		posts = append(posts, post)
	}

	return posts, nil
}
func GetPostsFromDB(startTime, endTime int64) ([]jsonprovider.GetPostResponse, error) {
	// 从数据库中获取帖子
	rows, err := db.Query("SELECT authorId, postId, content, time, comments FROM userposts WHERE time BETWEEN ? AND ?", startTime, endTime)
	if err != nil {
		logger.Error("Failed to get posts from DB:", err)
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			logger.Error("SQL错误", err)
		}
	}(rows)

	// 读取帖子
	var posts []jsonprovider.GetPostResponse
	for rows.Next() {
		var post jsonprovider.GetPostResponse
		err := rows.Scan(&post.AuthorID, &post.PostID, &post.Content, &post.Time, &post.Comments)
		if err != nil {
			logger.Error("Failed to read post:", err)
			return nil, err
		}
		posts = append(posts, post)
	}

	return posts, nil
}
