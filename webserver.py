from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import cgi

class webserverHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path.endswith("/hello"):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

                output = ""
                output += "<html><body>Hello!</body></html>"
                self.wfile.write(output)
        except IOError:
            self.send_error(404, "File Not Found {}".format(self.path))

    def do_POST(self):
        try:
            self.send_response(301)
            self.end_headers()

            ctype, pdict =  cgi.parse_header(
                self.headers.getheader('content-type'))
            if ctype == 'multipart/form-data':
                fields = cgi.parse_multipart(self.rfile, pdict)
                messagecontent = fields.get('message')

            output = (
                "<html><body>"
                " <h2? Okay, how about this: <h2>"
                "<h1> {} </h1>".format(messagecontent)[0])
            output += (
                "<form method='POST' enctype='multipart/form-data'"
                " action='/hello'><h2>What would you like me to say?</h2>"
                "<input name='message' type='text'>"



        except:

def main():
    try:
        port = 8080
        server = HTTPServer(('', port), webserverHandler)
        print "Web server is running on port {}".format(port)
        server.serve_forever()
    except KeyboardInterrupt:
        print("Finish")

if __name__ == "__main__":
    main()
