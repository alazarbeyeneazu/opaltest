package example.authz
import future.keywords
	
default allow := false

allow{
	pr:=get_user[_]
	some p in data.permissions
	o:=pr[_]
	p.id==o
	p.method==input.method
}

allow{
	pr:=get_user[_]
	some p in data.permissions
	o:=pr[_]
	p.id==o
	p.object=="manage"
	p.actions=="all"
}
get_user[permission.permissions]{
	input_user := input.subject
	some user in data.users
	user.id==input_user.id
	some role in data.roles
	role.id==user.role
	some permission in data.role_permissions
	permission.role==role.id
}	
	
allow{
	input.object.userid==input.subject.id
}