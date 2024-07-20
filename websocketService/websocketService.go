package websocketService

import (
	"Utils"
	"config"
	"database/sql"
	"dbUtils"
	"encoding/json"
	"hashUtils"
	jsonprovider "jsonProvider"
	"logger"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	Clients     = make(map[int]*jsonprovider.User) // 保存用户ID与用户结构体的映射关系
	ClientsLock sync.Mutex                         // 用于保护映射关系的互斥锁
)

var (
	configData config.Config
	db         *sql.DB
)

const (
	UserMessage = iota
	SystemMessage
)

func LoadConfig(conf config.Config) {
	configData = conf
}

func LoadDB(dbFromMain *sql.DB) {
	db = dbFromMain
}

//Message 消息结构体,用于临时消息池
//type Message struct {
//	tempID      int
//	id          int
//	messageBody string
//}

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {

	// 完成WebSocket握手
	var upgrader = websocket.Upgrader{
		ReadBufferSize:  configData.WebsocketConnBufferSize,
		WriteBufferSize: configData.WebsocketConnBufferSize,
	}

	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	defer func() {
		err := conn.Close()
		if err != nil {
			logger.Error(err)
		}
	}()
	if err != nil {
		logger.Error("WebSocket upgrade failed:", err)
		return
	}
	Logined := false
	var userID int
	var useHeartPack bool = true
	// 处理WebSocket消息
	for !Logined {
		_, message, err := conn.ReadMessage()
		if err != nil {
			logger.Debug("读取消息失败，可能是用户断开连接:", err)
			break
		}

		var pre jsonprovider.StandardJSONPack
		jsonprovider.ParseJSON(message, &pre)

		switch pre.Command {
		case configData.Commands.Heart:
			responsePack := jsonprovider.SdandarlizeJSON_byte(configData.Commands.Heart, &jsonprovider.HeartBeatPack{
				TimeStamp: time.Now().Local().UTC().Nanosecond(),
			})
			// 发送响应给请求者
			err := conn.WriteMessage(websocket.TextMessage, responsePack)
			if err != nil {
				logger.Error("心跳包回发错误:", err)
			}
		case configData.Commands.Login:
			var res jsonprovider.LoginResponse
			var p jsonprovider.LoginRequest
			jsonprovider.ParseJSON(pre.Content, &p)
			logger.Debug(p)

			userID = p.Userid
			useHeartPack = p.UseArtificialHeartPack

			passwordHash, passwordSalt, err := dbUtils.GetDBPasswordHash(userID)
			if err != nil {
				logger.Error("读取数据库密码哈希值失败", err)
				continue
			}
			logger.Debug("登录时读取盐:", passwordSalt)
			tryingPasswordHash := hashUtils.HashPassword(p.Password, passwordSalt)
			logger.Debug("尝试哈希", tryingPasswordHash, "实际哈希", passwordHash)
			if tryingPasswordHash == passwordHash {
				// 从数据库中获取用户信息
				var username, userAvatar, userNote string
				var userPermission uint
				var userFriendList json.RawMessage
				err := db.QueryRow("SELECT userName, userAvatar, userNote, userPermission, userFriendList FROM userdatatable WHERE userID = ?", userID).Scan(&username, &userAvatar, &userNote, &userPermission, &userFriendList)
				if err != nil {
					logger.Error("获取用户数据失败:", err)
					continue
				}
				var userState int
				if p.UserState != nil {
					userState = *p.UserState
				} else {
					userState = jsonprovider.Online
				} //指针判空，确认登陆状态

				// 创建新的User结构体
				user := &jsonprovider.User{
					UserId:         userID,
					Conn:           conn,
					UserName:       username,
					UserAvatar:     userAvatar,
					UserNote:       userNote,
					UserPermission: userPermission,
					UserFriendList: userFriendList,
					UserState:      &userState,
				}

				// 保存到clients map中
				ClientsLock.Lock()
				Clients[userID] = user
				ClientsLock.Unlock()

				res = jsonprovider.LoginResponse{
					StandardResponsePack: jsonprovider.StandardResponsePack{
						Success: true,
						Message: "登录成功",
					},
					UserData: user,
				}
				logger.Debug("用户", userID, "登录成功")
				Logined = true
			} else {
				res = jsonprovider.LoginResponse{
					StandardResponsePack: jsonprovider.StandardResponsePack{
						Success: false,
						Message: "登录失败",
					},
				}
			}
			message := jsonprovider.SdandarlizeJSON_byte(configData.Commands.Login, &res)
			err = conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				logger.Error("Failed to send message:", err)
				// 处理发送消息失败的情况
			}
		case configData.Commands.Register:
			var username, password string
			var user jsonprovider.SignUpRequest
			jsonprovider.ParseJSON(pre.Content, &user)
			username = user.UserName
			password = user.Password

			var resString string
			var state bool = false
			var userID int64

			if username == "" || password == "" {
				resString = "缺少参数"
			} else if Utils.Utf8RuneCountInString(username) > 10 {
				resString = "用户名不能超过10个字符"
			} else if len(password) < 8 || len(password) > 100 {
				resString = "密码必须在8-100个字符之间"
			} else if !Utils.ContainsLetterAndNumber(password) || !Utils.ContainsLowerAndUpperCase(password) {
				resString = "密码必须包含字母和数字，并且包含大小写字母"
			} else {
				// 进行注册逻辑的处理
				// 生成盐
				salt, err := hashUtils.GenerateSalt()
				if err != nil {
					logger.Error("密码加盐时出错:", err)
					resString = "密码加盐时出错"
				} else {
					// 哈希密码
					hashedPassword := hashUtils.HashPassword(password, salt)
					logger.Debug("注册时生成盐:", salt)

					// 将用户数据存入数据库
					userID, err = dbUtils.SaveUserToDB(username, hashedPassword, salt)
					if err != nil {
						logger.Error("用户注册时出现错误:", err)
						resString = "保存信息时出错"
					} else {
						// 返回用户唯一的自增ID
						resString = "注册成功"
						state = true
					}
				}
			}

			res := jsonprovider.SignUpResponse{
				StandardResponsePack: jsonprovider.StandardResponsePack{
					Success: state,
					Message: resString,
				},
				Userid: int(userID),
			}
			message := jsonprovider.SdandarlizeJSON_byte(configData.Commands.Register, &res)
			err = conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				logger.Error("Failed to send message:", err)
				// 处理发送消息失败的情况
			}
		}
	}

	//消息处理主循环
	var connState bool
	connState = true
	// 创建一个定时器，实现心跳包机制
	timer := time.NewTimer(time.Duration(configData.WebSocketHeartbeatTimeoutSeconds) * time.Second)
	go func() {
		<-timer.C // 阻塞直到定时器触发
		if useHeartPack {
			connState = false
		}
	}()
	for Logined {
		if !connState {
			break //跳出循环，释放资源
		}

		// 读取消息
		_, message, err := conn.ReadMessage()
		if err != nil {
			logger.Debug("读取消息失败，可能是用户断开连接:", err)
			break
		}

		// 在这里处理消息，用保存的映射关系来识别和处理特定用户的消息
		logger.Debug("Received message from user", userID, ":", string(message), "\n")
		timer.Reset(time.Duration(configData.WebSocketHeartbeatTimeoutSeconds) * time.Second) //重置心跳包
		var pre jsonprovider.StandardJSONPack
		jsonprovider.ParseJSON(message, &pre)
		switch pre.Command {
		case configData.Commands.Heart:
			responsePack := jsonprovider.SdandarlizeJSON_byte(configData.Commands.Heart, &jsonprovider.HeartBeatPack{
				TimeStamp: time.Now().Local().UTC().Nanosecond(),
			})
			// 发送响应给请求者
			//不走sendJSON，不然太费数据库了
			err := conn.WriteMessage(websocket.TextMessage, responsePack)
			if err != nil {
				logger.Error("心跳包回发错误:", err)
			}
		case configData.Commands.CheckUserOnlineState:
			// 解析请求
			var onlineStateRequest jsonprovider.CheckUserOnlineStateRequest
			jsonprovider.ParseJSON(pre.Content, &onlineStateRequest)

			// 检查用户在线状态
			ClientsLock.Lock()
			user, exists := Clients[onlineStateRequest.UserID]
			ClientsLock.Unlock()
			isOnline := exists && user.Conn != nil
			sendJSONToUser(userID, jsonprovider.CheckUserOnlineStateResponse{
				UserID:   onlineStateRequest.UserID,
				IsOnline: isOnline,
			}, configData.Commands.CheckUserOnlineState)
		case configData.Commands.SendUserMessage:
			var state int
			//获取基本信息
			var receivedPack jsonprovider.SendMessageRequest
			jsonprovider.ParseJSON(pre.Content, &receivedPack)
			timeStamp := int(time.Now().UnixNano())
			//保存到数据库，获取消息ID
			messageID, err := dbUtils.SaveMessageToDB(userID, receivedPack.TargetID, receivedPack.MessageBody, UserMessage)
			if err != nil {
				logger.Error("用户", receivedPack.TargetID, "发送信息时数据库插入失败")
				break
			}
			// 向指定用户发送消息
			isSent, msgerr := sendJSONToUser(receivedPack.TargetID, &jsonprovider.SendMessageToTargetPack{
				SenderID:    userID,
				MessageID:   messageID,
				MessageBody: receivedPack.MessageBody,
				TimeStamp:   timeStamp,
			}, configData.Commands.SendUserMessage)
			if !isSent {
				if msgerr == nil {
					logger.Info("用户", receivedPack.TargetID, "不在线，已保存到离线消息") //用原来消息的ID保存到离线消息表中
					_, err := dbUtils.SaveOfflineMessageToDB(messageID, userID, receivedPack.TargetID, receivedPack.MessageBody, UserMessage)
					if err != nil {
						logger.Error("保存离线消息失败", err)
						state = jsonprovider.ServerSendError
					}
					state = jsonprovider.UserIsNotOnline
				} else {
					state = jsonprovider.ServerSendError
				}
			} else {
				state = jsonprovider.UserReceived
			}
			//回发
			sendJSONToUser(userID, jsonprovider.SendMessageResponse{
				RequestID: receivedPack.RequestID,
				MessageID: messageID,
				TimeStamp: timeStamp,
				State:     state,
			}, configData.Commands.SendUserMessage)
		case configData.Commands.SendGroupMessage:
			var req jsonprovider.SendGroupMessageRequest
			jsonprovider.ParseJSON(pre.Content, &req)

			// 保存消息到数据库
			timeStamp := int(time.Now().UnixNano())
			var messageID int
			messageID, err = dbUtils.SaveGroupMessageToDB(userID, int(req.GroupID), req.MessageBody, UserMessage)
			if err != nil {
				logger.Error("用户发送群消息时数据库插入失败")
				connState = false
			}

			// 获取群成员
			var groupMembers []int
			err = db.QueryRow("SELECT groupMembers FROM groupdatatable WHERE groupID = ?", req.GroupID).Scan(&groupMembers)
			if err != nil {
				logger.Error("Failed to get group members:", err)
				return
			}

			// 向所有群成员发送消息
			for _, memberID := range groupMembers {
				onlineState, msgerr := sendJSONToUser(memberID, jsonprovider.SendMessageToGroupPack{
					SenderID:    userID,
					MessageID:   messageID,
					MessageBody: req.MessageBody,
					TimeStamp:   timeStamp,
				}, configData.Commands.MessageFromGroup)
				if !onlineState {
					if msgerr == nil {
						logger.Info("群聊中", memberID, "不在线，已保存到离线消息") //用原来消息的ID保存到离线消息表中
						dbUtils.SaveOfflineGroupMessageToDB(messageID, userID, memberID, req.MessageBody, UserMessage)
					}
				}
			}

			sendJSONToUser(userID, jsonprovider.SendGroupMessageResponse{
				RequestID: req.RequestID,
				MessageID: messageID,
				TimeStamp: timeStamp,
				State:     jsonprovider.UserReceived,
			}, configData.Commands.SendGroupMessage)
		case configData.Commands.AddFriend:
			var req jsonprovider.AddFriendRequest
			jsonprovider.ParseJSON(pre.Content, &req)

			// 获取用户的朋友列表
			friendList := Clients[userID].UserFriendList
			var friends []int
			err := json.Unmarshal(friendList, &friends)
			if err != nil {
				logger.Error("Failed to update friend list:", err)
				break
			}

			// 添加新朋友
			friends = append(friends, req.FriendID)

			// 更新朋友列表
			newFriendList, _ := json.Marshal(friends)
			Clients[userID].UserFriendList = newFriendList

			// 更新数据库
			_, err = db.Exec("UPDATE userdatatable SET userFriendList = ? WHERE userID = ?", newFriendList, userID)
			if err != nil {
				logger.Error("Failed to update friend list:", err)
			}

			sendJSONToUser(userID, jsonprovider.AddFriendResponse{
				UserID:   userID,
				FriendID: req.FriendID,
				StandardResponsePack: jsonprovider.StandardResponsePack{
					Success: err == nil,
				},
			}, configData.Commands.AddFriend)
		case configData.Commands.DeleteFriend:
			var req jsonprovider.DeleteFriendRequest
			jsonprovider.ParseJSON(pre.Content, &req)

			// 获取用户的朋友列表
			friendList := Clients[userID].UserFriendList
			var friends []int
			err := json.Unmarshal(friendList, &friends)
			if err != nil {
				break
			}

			// 删除朋友
			for i, friend := range friends {
				if friend == req.FriendID {
					friends = append(friends[:i], friends[i+1:]...)
					break
				}
			}

			// 更新朋友列表
			newFriendList, _ := json.Marshal(friends)
			Clients[userID].UserFriendList = newFriendList

			// 更新数据库
			_, err = db.Exec("UPDATE userdatatable SET userFriendList = ? WHERE userID = ?", newFriendList, userID)
			if err != nil {
				logger.Error("Failed to update friend list:", err)
			}

			sendJSONToUser(userID, jsonprovider.DeleteFriendResponse{
				UserID:   userID,
				FriendID: req.FriendID,
				StandardResponsePack: jsonprovider.StandardResponsePack{
					Success: err == nil,
				},
			}, configData.Commands.DeleteFriend)
		case configData.Commands.ChangeFriendSettings:
		case configData.Commands.CreateGroup:
			var req jsonprovider.CreateGroupRequest
			jsonprovider.ParseJSON(pre.Content, &req)

			// 在数据库中创建新的群聊
			res, err := db.Exec("INSERT INTO groupdatatable (groupName, groupExplaination, groupMaster) VALUES (?, ?, ?)", req.GroupName, req.GroupExplaination, userID)
			if err != nil {
				logger.Error("Failed to create group:", err)
				return
			}

			// 获取新群聊的ID
			groupID, err := res.LastInsertId()
			if err != nil {
				logger.Error("Failed to get group ID:", err)
				return
			}

			// 创建新的群聊成员列表
			var groupMembers jsonprovider.GroupMembers
			groupMembers = append(groupMembers, jsonprovider.GroupMember{
				UserID:     userID,
				Permission: jsonprovider.Owner,
			})

			// 更新群聊的成员列表
			groupMembersJSON := jsonprovider.StringifyJSON(groupMembers)
			_, err = db.Exec("UPDATE groupdatatable SET groupMembers = ? WHERE groupID = ?", groupMembersJSON, groupID)
			if err != nil {
				logger.Error("Failed to update group members:", err)
			}

			sendJSONToUser(userID, jsonprovider.CreateGroupResponse{
				GroupID: groupID,
				StandardResponsePack: jsonprovider.StandardResponsePack{
					Success: err == nil,
				},
			}, configData.Commands.CreateGroup)
		case configData.Commands.BreakGroup:
			var req jsonprovider.BreakGroupRequest
			jsonprovider.ParseJSON(pre.Content, &req)

			// 在数据库中删除群聊
			_, err := db.Exec("DELETE FROM groupdatatable WHERE groupID = ? AND groupMaster = ?", req.GroupID, userID)
			//只有群主有权限解散群聊
			if err != nil {
				logger.Error("Failed to break group:", err)
				return
			}

			sendJSONToUser(userID, jsonprovider.BreakGroupResponse{
				GroupID: req.GroupID,
				StandardResponsePack: jsonprovider.StandardResponsePack{
					Success: err == nil,
				},
			}, configData.Commands.BreakGroup)
		case configData.Commands.ChangeGroupSettings:
		case configData.Commands.GetUserData:
			var req jsonprovider.GetUserDataRequest
			jsonprovider.ParseJSON(pre.Content, &req)

			// 从数据库中获取用户数据
			res, err := dbUtils.GetUserFromDB(userID)
			if err != nil {
				logger.Error("Failed to get user data:", err)
				return
			}
			sendJSONToUser(userID, res, configData.Commands.GetUserData)
		case configData.Commands.MessageEvent:
		case configData.Commands.UserStateEvent: //不具备缓存性质
			var req jsonprovider.ChangeStateRequest
			jsonprovider.ParseJSON(pre.Content, &req)
			ClientsLock.Lock()
			Clients[userID].UserState = &req.UserState
			ClientsLock.Unlock()
			var friends []int
			jsonprovider.ParseJSON(Clients[userID].UserFriendList, &friends)
			var state int
			if *Clients[userID].UserState != jsonprovider.Stealth {
				state = *Clients[userID].UserState
			} else {
				state = jsonprovider.Offline
			}
			for _, friendId := range friends {

				sendJSONToUser(friendId, jsonprovider.UserStateEvent{
					UserID:    friendId,
					UserState: state,
				}, configData.Commands.UserStateEvent)

			}
		case configData.Commands.GetOfflineMessage:
			handleGetOfflineMessages(userID)
		case configData.Commands.GetMessagesWithUser:
			var req jsonprovider.GetMessagesWithUserRequest
			jsonprovider.ParseJSON(pre.Content, &req)

			// 从数据库中查询聊天记录
			rows, err := db.Query("SELECT messageID, senderID, receiverID, time, messageBody, messageType FROM messages WHERE ((senderID = ? AND receiverID = ?) OR (senderID = ? AND receiverID = ?)) AND time BETWEEN ? AND ?", userID, req.OtherUserID, req.OtherUserID, userID, req.StartTime, req.EndTime)
			if err != nil {
				logger.Error("Failed to get messages:", err)
				return
			}

			// 读取聊天记录
			var messages []jsonprovider.Message
			for rows.Next() {
				var message jsonprovider.Message
				err := rows.Scan(&message.MessageID, &message.SenderID, &message.ReceiverID, &message.Time, &message.MessageBody, &message.MessageType)
				if err != nil {
					logger.Error("Failed to read message:", err)
					return
				}
				messages = append(messages, message)
			}
			err = rows.Close()
			if err != nil {
				logger.Error(err)
			}
			sendJSONToUser(userID, jsonprovider.GetMessagesWithUserResponse{
				UserID:   userID,
				Messages: messages,
			}, configData.Commands.GetMessagesWithUser)
		case configData.Commands.ChangeSettings:
		case configData.Commands.ChangeAvatar:
			var req jsonprovider.ChangeAvatarRequest
			jsonprovider.ParseJSON(pre.Content, &req)

			// 更新用户结构体
			Clients[userID].UserAvatar = req.NewAvatar

			// 更新数据库
			_, err := db.Exec("UPDATE userdatatable SET userAvatar = ? WHERE userID = ?", req.NewAvatar, userID)
			if err != nil {
				logger.Error("Failed to update avatar:", err)
			}
			// 发送响应
			sendJSONToUser(userID, jsonprovider.ChangeAvatarResponse{
				UserID:    userID,
				NewAvatar: req.NewAvatar,
				StandardResponsePack: jsonprovider.StandardResponsePack{
					Success: err == nil,
				},
			}, configData.Commands.ChangeAvatar)
		case configData.Commands.Logout:
			connState = false
		}

	}

	//TODO 1.加好友包 2.申请加入群聊 3.消息验证 4.测试离线消息

	// 用户断开连接
	// 在此处删除映射关系
	connState = false
	if Logined {

		var friends []int
		jsonprovider.ParseJSON(Clients[userID].UserFriendList, &friends)

		for _, friendId := range friends {
			if *Clients[userID].UserState != jsonprovider.Stealth {
				sendJSONToUser(friendId, jsonprovider.UserStateEvent{
					UserID:    friendId,
					UserState: jsonprovider.Offline,
				}, configData.Commands.UserStateEvent)
			}
		}
		ClientsLock.Lock()
		delete(Clients, userID)
		ClientsLock.Unlock()
		logger.Info("用户", userID, "已断开连接")

	}

}

func BroadcastMessage(message []byte) {
	ClientsLock.Lock()
	defer ClientsLock.Unlock()

	for _, client := range Clients {
		sendJSONToUser(client.UserId, jsonprovider.BroadcastMessage{
			Message: string(message),
		}, configData.Commands.BroadcastMessage)
	}
}

func sendJSONToUser(userID int, msg interface{}, command string) (bool, error) {
	message := jsonprovider.SdandarlizeJSON_byte(command, msg)
	userOnline, err := sendMessageToUser(userID, []byte(message))
	if err != nil {
		logger.Error("err in func sendJSONToUser :", err)
	}
	return userOnline, err
}

func sendMessageToUser(userID int, message []byte) (bool, error) {
	ClientsLock.Lock()
	defer ClientsLock.Unlock()

	client, ok := Clients[userID]
	if !ok {
		logger.Warn("用户不在线:", userID)
		return false, nil
	}
	logger.Debug("服务器回发包：", message)
	err := client.Conn.WriteMessage(websocket.TextMessage, message)
	if err != nil {
		logger.Error("消息发送失败:", err)
		// 处理发送消息失败的情况
		return false, err
	}

	return true, nil
}
func handleGetOfflineMessages(userID int) {
	// 从数据库中获取离线消息
	rows, err := db.Query("SELECT messageID, senderID, receiverID, time, messageBody, messageType FROM offlinemessages WHERE receiverID = ?", userID)
	if err != nil {
		logger.Error("Failed to get offline messages:", err)
		return
	}

	// 读取离线消息
	var messages []jsonprovider.Message
	for rows.Next() {
		var message jsonprovider.Message
		err := rows.Scan(&message.MessageID, &message.SenderID, &message.ReceiverID, &message.Time, &message.MessageBody, &message.MessageType)
		if err != nil {
			logger.Error("Failed to read message:", err)
			return
		}
		messages = append(messages, message)
	}
	err = rows.Close()
	if err != nil {
		logger.Error("Failed to close rows:", err)
	}

	// 删除已读的离线消息
	_, err = db.Exec("DELETE FROM offlinemessages WHERE receiverID = ?", userID)
	if err != nil {
		logger.Error("Failed to delete offline messages:", err)
	}

	// 创建响应
	sendJSONToUser(userID, jsonprovider.GetOfflineMessagesResponse{
		State:    true,
		Messages: messages,
	}, configData.Commands.GetOfflineMessage)
}
