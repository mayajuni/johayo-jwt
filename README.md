#Johayo JWT

##����
 ���� JWT �̵��� ����Ͽ�, express���� ����ϱ� ���ϰ� ��������ϴ�.
JWT�� ���� ������ <a href='http://jwt.io' target='_black'>Go to jwt.io</a>���� Ȯ���غ��ø� �˴ϴ�. 

##��ġ
```javascript
$ npm install johayo-jwt
```

##���
���� ���� jwt�� �ѹ��� ��ȣȭ�� �����Ͽ� ���ȿ� ���� �Ű� �� Ÿ���Դϴ�. �׸��� ����ð��� �ξ� ���� ȿ�������� ��� �����ϰ� �Ͽ����ϴ�. ��ȣȭ�� �� �������� ������ ���� ���� ������ =='req.user'==�� ����˴ϴ�.

####1. ����
```javascript
var johayoJwt = require("johayo-jwt");

app.use(johayoJwt({
    /* jwt ��ū�� �����ͺκ��� �ѹ��� ��ȣȭ �Ҷ� ���� ��ȣȭŰ */
    tokenSecret: "SecretKey",
    /* jwt ��ü ��ȣȭ Ű */
    jwtSecret: "SecretKey",
    /* jwt ��ȣȭ �˰���(����Ʈ: HS256) */
    algorithm: "HS256",
    /* ����ð� �ʴ��� (����Ʈ: 3600 - 1�ð�) */
    expireTime: 3600,
    /* ��ȣȭ ���� ���� ������ġ(����Ʈ: req.user) */
    userProperty: "user"
}))
```
####2. ��ȣȭ
```javascript
app.get('/', johayoJwt.verify, function(req, res){
    console.log(req.user);
})
```

####3. ��ȣȭ
```javascript
johayoJwt.encode(data);
```

####4. ����
������ ���� throw�� ó�� �Ǹ� ��ȣȭ �� error status�� 401�� ���� �˴ϴ�. ���� �޼����� jsonwebtoken�� ���� �޽����� ���� �Ͻø� �˴ϴ�. �׿� �����޼����� �Ʒ��� �����ϴ�.
	- Format is Authorization: Bearer 'token'
	- req.headers.authorization was not found

####5. ���� jsonwebtoken �ٸ���
���� ����ϴ� express���� ����ϱ� ���ϰ� ���������, ����ð��� �ʼ��� ���� �س����ϴ�. �׸��� jsonwebtoken�� �̿��� ��ȣȭ �� ���� �ѹ��� ��ȣȭ �ϴ� ����� ä���߽��ϴ�. jwt ��ü�� ��ȣȭ ������ �ʰ� jwt���� base64�� ��ȣȭ�� claim json�κ��� �ѹ� �� aes 256 cbc ��ȣȭ �˰������� ��ȣȭ �Ͽ����ϴ�.

