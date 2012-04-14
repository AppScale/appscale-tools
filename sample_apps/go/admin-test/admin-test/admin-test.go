// Programmer: Chris Bunch

package admin_test

import (
	"fmt"
	"http"

	"appengine"
	"appengine/user"
)

func init() {
	http.HandleFunc("/", test)
}

func test(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	loginURL, _ := user.LoginURL(c, r.URL.String())
	logoutURL, _ := user.LogoutURL(c, r.URL.String())

	fmt.Fprintf(w, "<a href='%v'>Login</a><hr />", loginURL)
	fmt.Fprintf(w, "<a href='%v'>Logout</a><hr />", logoutURL)

	u := user.Current(c)
	if u == nil {
		fmt.Fprintf(w, "you are not logged in")
	} else {
		if user.IsAdmin(c) {
			fmt.Fprintf(w, "you are an administrator")
		} else {
			fmt.Fprintf(w, "you are logged in but not admin")
		}
	}
}
