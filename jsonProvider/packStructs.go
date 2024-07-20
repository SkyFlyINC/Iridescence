package jsonprovider

import (
	"encoding/json"
)

//消息体一律称为MessageBody，而不称为Content。MessageBody可以发挥MessageChain的功能

// StandardJSONPack 根数据包结构体，仅用于websocket
type StandardJSONPack struct {
	Command string          `json:"command"`
	Content json.RawMessage `json:"content"`
}

// Success是布尔值，State是int
type StandardResponsePack struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

type HeartBeatPack struct {
	TimeStamp int `json:"timeStamp"`
}

type LoginRequest struct {
	Userid                 int    `json:"userId"`
	Password               string `json:"password"`
	UseArtificialHeartPack bool   `json:"heartPack"`
	UserState              *int   `json:"userState"`
}
type LoginResponse struct {
	StandardResponsePack
	UserData *User `json:"userData,omitempty"`
}
type SignUpRequest struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
}

type SignUpResponse struct {
	StandardResponsePack
	Userid int `json:"userId"`
}
type SendMessageRequest struct {
	TargetID         int    `json:"targetId"`    //消息接收人
	RequestID        int    `json:"requestId"`   //request ID由客户端生成
	MessageBody      string `json:"messageBody"` //消息体
	RequestTimeStamp int    `json:"time"`        //判断请求是否合法，是否超时
}

// SendMessageResponse 实现ACK机制
type SendMessageResponse struct {
	RequestID int `json:"requestId"` //返回requestID，用于ACK机制
	MessageID int `json:"messageId"` //返回递增的数据库主键，作为MessageID,用户可以用messageID进行后续的撤回，引用等操作
	TimeStamp int `json:"time"`
	State     int `json:"state"`
}

// 错误等级
const (
	UserRefused = iota
	ServerSendError
	UserIsNotOnline
	UserReceived
)

type SendMessageToTargetPack struct {
	SenderID    int    `json:"senderId"`
	MessageID   int    `json:"messageId"`
	MessageBody string `json:"messageBody"`
	TimeStamp   int    `json:"time"`
}
type SendMessagePackResponseFromUser struct {
	StandardResponsePack
	MessageID int `json:"messageId"`
}

type AddFriendRequest struct {
	FriendID int `json:"friendId"`
}

type AddFriendResponse struct {
	UserID   int `json:"userId"`
	FriendID int `json:"friendId"`
	StandardResponsePack
}

// 加好友要求对方同意的数据包通过sendUserMessage实现
type DeleteFriendRequest struct {
	FriendID int `json:"friendId"`
}

type CheckUserOnlineStateRequest struct {
	UserID int `json:"userId"`
}

type CheckUserOnlineStateResponse struct {
	UserID   int  `json:"userId"`
	IsOnline bool `json:"isOnline"`
}

type GetUserDataRequest struct {
	UserID int `json:"userId"`
}

type GetUserDataResponse struct {
	UserID         int             `json:"userId"`
	UserName       string          `json:"userName"`
	UserAvatar     string          `json:"userAvatar"`
	UserNote       string          `json:"userNote"`
	UserPermission uint            `json:"userPermission"`
	UserFriendList json.RawMessage `json:"userFriendList"`
}

type ChangeAvatarRequest struct {
	NewAvatar string `json:"newAvatar"`
}

type ChangeAvatarResponse struct {
	UserID    int    `json:"userId,omitempty"`
	NewAvatar string `json:"newAvatar,omitempty"`
	StandardResponsePack
}

type GetMessagesWithUserRequest struct {
	OtherUserID int `json:"otherUserId"`
	StartTime   int `json:"startTime"`
	EndTime     int `json:"endTime"`
}

type GetMessagesWithUserResponse struct {
	UserID   int       `json:"userId"`
	Messages []Message `json:"messages"`
}

type Message struct {
	MessageID   int    `json:"messageId"`
	SenderID    int    `json:"senderId"`
	ReceiverID  int    `json:"receiverId"`
	Time        int    `json:"time"`
	MessageBody string `json:"messageBody"`
	MessageType int    `json:"messageType"`
}

type CreateGroupRequest struct {
	GroupName         string `json:"groupName"`
	GroupExplaination string `json:"groupExplaination"`
}

type CreateGroupResponse struct {
	GroupID int64 `json:"groupId,omitempty"`
	StandardResponsePack
}
type BreakGroupRequest struct {
	GroupID int64 `json:"groupId,omitempty"`
}

type BreakGroupResponse struct {
	GroupID int64 `json:"groupId,omitempty"`
	StandardResponsePack
}
type SendGroupMessageRequest struct {
	GroupID     int64  `json:"groupId"`
	MessageBody string `json:"messageBody"`
	RequestID   int    `json:"requestId"`
}

type SendGroupMessageResponse struct {
	RequestID int `json:"requestId"`
	MessageID int `json:"messageId"`
	TimeStamp int `json:"timeStamp"`
	State     int `json:"state"`
}

type SendMessageToGroupPack struct {
	SenderID    int    `json:"senderId"`
	MessageID   int    `json:"messageId"`
	MessageBody string `json:"messageBody"`
	TimeStamp   int    `json:"timeStamp"`
}

type RequestToBeAddedAsFriend struct {
	ReceiverID int    `json:"receiverId"`
	TimeStamp  int    `json:"timeStamp"`
	Message    string `json:"message"`
}

type RequestToBeAddedIntoGroup struct {
	GroupID   int    `json:"groupId"`
	TimeStamp int    `json:"timeStamp"`
	Message   string `json:"message"`
}

type RequestToBeAddedAsFriendFromUser struct {
	ReceiverID int    `json:"receiverId"`
	TimeStamp  int    `json:"timeStamp"`
	Message    string `json:"message"`
}

type RequestToBeAddedIntoGroupFromUser struct {
	GroupID   int    `json:"groupId"`
	TimeStamp int    `json:"timeStamp"`
	Message   string `json:"message"`
}

type RequestToQuitFromGroup struct {
	UserID  int `json:"userId"`
	GroupID int `json:"groupId"`
}

const (
	Banned = iota
	OrdinaryMember
	Operator
	Owner
)

type ChangeMemberPermissionInGroup struct {
	GroupID       int `json:"groupId"`
	UserID        int `json:"userId"`
	NewPermission int `json:"newPermission"`
}

type ChangePasswordRequest struct {
	UserID      int    `json:"userId"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type AddUserToGroupRequest struct {
	GroupID int `json:"groupId"`
	UserID  int `json:"userId"`
}

type DeleteFriendResponse struct {
	UserID   int `json:"userId"`
	FriendID int `json:"friendId"`
	StandardResponsePack
}
type GetOfflineMessagesResponse struct {
	State    bool      `json:"state"`
	Messages []Message `json:"messages"`
}
type PublishPostRequest struct {
	UserID  int    `json:"userId"`
	Content string `json:"content"`
}

type PublishPostResponse struct {
	Success bool `json:"success"`
}
type GetPostRequest struct {
	PostID int64 `json:"postId"`
}

type GetPostResponse struct {
	AuthorID int    `json:"authorId"`
	PostID   int64  `json:"postId"`
	Content  string `json:"content"`
	Time     int64  `json:"time"`
	Comments string `json:"comments"`
}

type GetUserPostsRequest struct {
	UserID    int   `json:"userId"`
	StartTime int64 `json:"startTime"`
	EndTime   int64 `json:"endTime"`
}

type GetUserPostsResponse struct {
	UserID int               `json:"userId"`
	Posts  []GetPostResponse `json:"posts"`
}
type GetPostsRequest struct {
	StartTime int64 `json:"startTime"`
	EndTime   int64 `json:"endTime"`
}

type GetPostsResponse struct {
	Posts []GetPostResponse `json:"posts"`
}

type BroadcastMessage struct {
	Message string `json:"message"`
}

//Events

type UserStateEvent struct {
	UserID    int `json:"userId"`
	UserState int `json:"userState"`
}

type ChangeStateRequest struct {
	UserState int `json:"userState"`
}
