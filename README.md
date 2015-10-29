#Johayo JWT
 기존 JWT 미들웨어를 사용하여, express에서 사용하기 편하게 만들었습니다.
JWT에 대한 설명은 <a href='http://jwt.io' target='_black'>Go to jwt.io</a>에서 확인해보시면 됩니다. 

##설치
```javascript
$ npm install johayo-jwt
```

##업데이트
 socketIO에서 사용하기 편하게 변경 처리.

##사용
제가 만든 jwt는 한번더 암호화를 진행하여 보안에 조금 신경 쓴 타입입니다. 그리고 만료시간을 두어 좀더 효과적으로 사용 가능하게 하였습니다. 복호화한 후 정보들은 설정을 따로 하지 않으면 ```'req.user'```에 저장됩니다.

####1. 설정
```javascript
var johayoJwt = require("johayo-jwt");

app.use(johayoJwt({
    /* jwt 토큰의 데이터부분을 한번더 암호화 할때 쓰는 암호화키 */
    tokenSecret: "SecretKey",
    /* jwt 자체 암호화 키 */
    jwtSecret: "SecretKey",
    /* jwt 암호화 알고리즘(디폴트: HS256) */
    algorithm: "HS256",
    /* 만료시간 초단위 (디폴트: 3600 - 1시간) */
    expireTime: 3600,
    /* 복호화 한후 정보 저장위치(디폴트: req.user) */
    userProperty: "user"
}))
```
####2. 복호화
```javascript
app.get('/', johayoJwt.verify, function(req, res){
    console.log(req.user);
})
```

####3. 암호화
```javascript
johayoJwt.encode(data, expireTime);
```
expireTime 없으면 기존 설정한데로 들어간다.


####4. 에러
에러는 전부 throw로 처리 되며 복호화 시 error status는 401로 셋팅 됩니다. 에러 메세지는 jsonwebtoken의 에러 메시지를 참고 하시면 됩니다. 그외 에러메세지는 아래와 같습니다.
- Format is Authorization: Bearer 'token'
- req.headers.authorization was not found

####5. 기존 jsonwebtoken 다른점
자주 사용하는 express에서 사용하기 편하게 만들었으며, 만료시간을 필수로 놓게 해놨습니다. 그리고 jsonwebtoken를 이용한 암호화 한 것을 한번더 암호화 하는 방식을 채택했습니다. jwt 전체를 암호화 하지는 않고 jwt에서 base64로 암호화한 claim json부분을 한번 더 aes 256 cbc 암호화 알고리즘으로 암호화 하였습니다.

