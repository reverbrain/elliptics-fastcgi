import requests

def upload_file (filename, data, embed = False, timestamp = 0):
	if embed:
		filename = filename + "?embed&timestamp=" + str (timestamp)
	r = requests.post ("http://localhost:9000/upload/" + str (filename), data = data)
	return r

def delete_file (filename):
	r = requests.get ("http://localhost:9000/delete/" + str (filename))
	return r

def get_file (filename, embed = False):
	if embed:
		filename = filename + "?embed"
	r = requests.get ("http://localhost:80/get/" + str (filename))
	return r

def prepare_file (filename, data, size):
	r = requests.post ("http://localhost:9000/upload/" + str (filename) + "?prepare=" + str (size), data = data)
	return r

def plain_write_file (filename, data, offset):
	r = requests.post ("http://localhost:9000/upload/" + str (filename) + "?plain_write&offset=" + str (offset), data = data)
	return r

def commit_file (filename, data, offset, size):
	r = requests.post ("http://localhost:9000/upload/" + str (filename) + "?commit=" + str(size) + "&offset=" + str (offset), data = data)
	return r

def bulk_write (files):
	boundary = "----------------------------17cccea874e5"
	CRLF = "\r\n"
	L = []
	for key in files:
		L.append ("--" + boundary)
		L.append ('Content-Disposition: form-data; name="%s"' % key)
		L.append ("Content-Type: application/octet-stream")
		L.append ("")
		L.append (files [key])
	L.append ("--" + boundary + "--")
	L.append ("")
	body = CRLF.join (L)
	headers = {
	"content-type": "multipart/form-data; boundary=" + boundary,
	"content-length": str (len (body))
	}
	r = requests.post ("http://localhost:9000/bulk-write", headers = headers, data = body)
	return r

def bulk_read (keys):
	body = "\n".join (keys)
	r = requests.post ("http://localhost:80/bulk-read", data = body)
	return r

def request_successful (r):
	if r.status_code != 200:
		raise Exception ("Request failed. Status code: " + str (r.status_code))

def verify_data (filename, data, embed = False):
	r = get_file (filename, embed)
	request_successful (r)
	if r.content != data:
		raise Exception ("Wrong content: " + str (r.content) + ". Expected content: " + str (data))

def expected_bulk_read (files):
	L = []
	for key in files:
		data = files [key]
		L.append (hex (len (data)) [2:] + '; name="' + key + '"')
		L.append (data)
	L.append ("0")
	L.append ("")
	L.append ("")
	body = "\r\n".join (L)
	return body

def compare_bulk_data (files, content):
	d = {}
	for k in files:
		f = open (k, "rb")
		s = "".join (f.readlines ())
		d [k] = s
	s = expected_bulk_read (d)
	if s != content:
		raise Exception ("Wrong content: " + str (content) + ". Expected content: " + str (s))

def test1 ():
	embed = True
	filename = "file1.txt"
	data = "Test data"
	print "*INFO* Upload"
	r = upload_file (filename, data, embed = embed, timestamp = 3)
	request_successful (r)
	print "*INFO* Verify"
	verify_data (filename, data, embed)
	print "*INFO* Delete"
	r = delete_file (filename)
	request_successful (r)

def test2 ():
	filename = "file1.txt"
	data = "Test data"
	print "*INFO* Prepare"
	r = prepare_file (filename, data [:2], len (data))
	request_successful (r)
	print "*INFO* Plain write"
	r = plain_write_file (filename, data [2:6], 2)
	request_successful (r)
	print "*INFO* Commit"
	r = commit_file (filename, data [6:], 6, len(data))
	request_successful (r)
	print "*INFO* Verify"
	verify_data (filename, data)
	print "*INFO* Delete"
	r = delete_file (filename)
	request_successful (r)

def test3 ():
#	files = {"file1.txt": open("file1.txt", "rb"),
#			 "file2.ttx": open ("tmp2", "rb")}
#	test3 ()
#	headers = {"content-type": "multipart/form-data"}
#	r = requests.post ("http://localhost:9000/bulk-write", files = files)

	keys = ["file1.txt", "file2.txt"]
	data = [open ("file1.txt", "rb"), open ("file2.txt", "rb")]
	files = dict(zip(keys, data))
	print "*INFO* Bulk write"
	r = requests.post ("http://localhost:9000/bulk-write", files = files)
#	r = bulk_write (files)
	request_successful (r)
	print "*INFO* Bulk read"
	r = bulk_read (keys)
	request_successful (r)
	print "*INFO* Bulk Verify"
#	s = expected_bulk_read (files)
#	if r.content != s:
#		raise Exception ("Wrong content: " + str (r.content) + ". Expected content: " + str (s))
	compare_bulk_data(keys, r.content)
	print "*INFO* Delete"
	for filename in keys:
		print "*INFO* Delete " + filename
		r = delete_file (filename)
		request_successful (r)

if __name__ == "__main__":
	test1 ()
	test2 ()
#	files = {"file1" : "data1", "file2" : "data2"}
	
#files = {"file1" : "file2"}
#	data = {"data1" : "data2"}
#	files = {"file": ("userfile", open("tmp", "rb")),
#			 "fil2": ("userfil2", open("tmp2", "rb"))}
	test3 ()
