package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

const PORT = 9191
const ENV_FILENAME string = "taju.env"

type tajiEvent struct {
	date string
	time string
}

type runDetails struct {
	date             string
	time             string
	time_hours       string
	time_minutes     string
	time_ampm        string
	distance         string
	duration         string
	duration_hours   string
	duration_minutes string
	duration_seconds string
	elevation_gain   string
	distance_float   float64
	duration_int     int64
}

type strava struct {
	token *oauth2.Token
	conf  *oauth2.Config
	ctx   context.Context
}

type taji struct {
	jar            http.CookieJar
	client         *http.Client
	csrf           string
	session        string
	participant_id string
}

type uploader struct {
	env    map[string]string
	strava strava
	taji   taji
}

func initUploader(u *uploader) {
	loadEnvFile(u)
	initStrava(u.env, &u.strava)
	initTaji(u.env, &u.taji)
	dumpEnvFile(u)
	log.Print("Initialized successfully.")
}

func loadEnvFile(u *uploader) {
	env, err := godotenv.Read(ENV_FILENAME)
	if err != nil {
		log.Fatal("Error loading file: '", ENV_FILENAME, "'. Make sure that it is in the same directory as this executable.")
	}
	u.env = env
}

func initStrava(env map[string]string, s *strava) {
	if _, ok := env["TAJU_CLIENT_ID"]; !ok {
		log.Fatal("Error unpacking TajUploader Client ID")
	}

	if _, ok := env["TAJU_CLIENT_SECRET"]; !ok {
		log.Fatal("Error unpacking TajUploader Client Secret")
	}

	s.ctx = context.Background()
	s.conf = &oauth2.Config{
		ClientID:     env["TAJU_CLIENT_ID"],
		ClientSecret: env["TAJU_CLIENT_SECRET"],
		RedirectURL:  fmt.Sprintf("http://localhost:%d", PORT),
		Scopes:       []string{"read,activity:read"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.strava.com/oauth/authorize",
			TokenURL: "https://www.strava.com/oauth/token",
		},
	}

	if token, ok := env["STRAVA_TOKEN"]; ok {
		json.Unmarshal([]byte(token), &s.token)
		log.Print("Successfully loaded Strava Oauth token")
	} else {
		authStrava(s)
		token, _ := json.Marshal(s.token)
		env["STRAVA_TOKEN"] = string(token)
	}
}

func authStrava(s *strava) {
	fmt.Printf("We need to authorize Taj Uploader to access your Strava account...")
	fmt.Printf("please visit the URL for the authorization dialog:\n\n%v\n\n", s.conf.AuthCodeURL("startup"))

	var code string
	server := &http.Server{
		Addr: "localhost:9191",
	}
	redirectHandler := func(w http.ResponseWriter, r *http.Request) {
		params, _ := url.ParseQuery(r.URL.RawQuery)
		code = params.Get("code")
		if code != "" {
			fmt.Fprintf(w, "Successful authorization!")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			server.Close()
		}

	}
	http.HandleFunc("/", redirectHandler)
	server.ListenAndServe()

	tok, err := s.conf.Exchange(s.ctx, code)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Print("Successful authorization")
	}
	s.token = tok
}

func initTaji(env map[string]string, t *taji) {
	var err error

	t.jar, err = cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new HTTP client with the cookie jar
	t.client = &http.Client{Jar: t.jar}

	var (
		csrf_ok bool
		sess_ok bool
		part_ok bool
	)
	t.csrf, csrf_ok = env["TAJI_CSRF"]
	t.session, sess_ok = env["TAJI_SESSION"]
	t.participant_id, part_ok = env["TAJI_PARTICIPANT"]

	if !(csrf_ok && sess_ok && part_ok) {
		loginTaji(t)
		env["TAJI_CSRF"] = t.csrf
		env["TAJI_SESSION"] = t.session
		env["TAJI_PARTICIPANT"] = t.participant_id
	} else {
		log.Print("Successfully loaded Taji session tokens")
	}

	csrf_cookie := &http.Cookie{
		Name:  "csrftoken",
		Value: env["TAJI_CSRF"]}

	sess_cookie := &http.Cookie{
		Name:  "sessionid",
		Value: env["TAJI_SESSION"]}

	u, err := url.Parse("https://taji100.com")
	if err != nil {
		log.Fatal("Failed to parse taji url.")
	}
	t.jar.SetCookies(u, []*http.Cookie{csrf_cookie, sess_cookie})

}

func loginTaji(t *taji) {
	main_url := "https://taji100.com"
	login_url := "https://taji100.com/account/login/"

	res, err := t.client.Get(login_url)
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	pattern := regexp.MustCompile(`<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' \/>`)
	match := pattern.FindSubmatch(body)
	csrfmiddlewaretoken := string(match[1]) // Get the captured group

	var (
		username string
		password string
	)

	fmt.Print("Enter your Taji100 username (it should be your email address) and hit ENTER: ")
	fmt.Scanln(&username)
	fmt.Print("Enter your Taji100 password and hit ENTER: ")
	fmt.Scanln(&password)

	values := url.Values{}
	values.Add("csrfmiddlewaretoken", csrfmiddlewaretoken)
	values.Add("email", username)
	values.Add("password", password)
	values.Encode()

	req, err := http.NewRequest("POST", login_url, strings.NewReader(values.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Referer", login_url)

	res, err = t.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	for _, cookie := range t.client.Jar.Cookies(res.Request.URL) {
		if cookie.Name == "csrftoken" {
			t.csrf = cookie.Value
		}
		if cookie.Name == "sessionid" {
			t.session = cookie.Value
		}
	}

	res, err = t.client.Get(main_url)
	if err != nil {
		log.Fatal(err)
	}

	body, err = io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	pattern = regexp.MustCompile(`<a class="nav-link w-nav-link" href="/participants/(.*?)/">My Page</a>`)
	match = pattern.FindSubmatch(body)
	t.participant_id = string(match[1])
}

func dumpEnvFile(u *uploader) {
	err := godotenv.Write(u.env, ENV_FILENAME)
	if err != nil {
		log.Print("Failed to write tokens to", ENV_FILENAME)
	}
}

func getStravaActivities(s *strava) (stravaActivities []runDetails) {
	startDate, _ := time.Parse("2006-01-02T15:04:05", "2025-02-01T00:00:00")
	endDate, _ := time.Parse("2006-01-02T15:04:05", "2025-03-01T00:00:00")

	client := s.conf.Client(s.ctx, s.token)

	api_endpoint := fmt.Sprintf(
		"https://www.strava.com/api/v3/athlete/activities?after=%d&before=%d&per_page=100",
		startDate.Unix(),
		endDate.Unix())

	req, err := http.NewRequest("GET", api_endpoint, nil)
	if err != nil {
		log.Print(err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", s.token.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		log.Print(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Print(err)
	}

	var activities []map[string]interface{}
	err = json.Unmarshal(body, &activities)
	if err != nil {
		log.Print("Error:", err)
		return
	}

	for _, activity := range activities {
		if activity["type"].(string) == "Run" {
			run := createRun(
				activity["start_date"].(string),
				int64(activity["elapsed_time"].(float64)),
				activity["distance"].(float64))
			stravaActivities = append(stravaActivities, run)
		}
	}
	return
}

func getTajiEntries(t *taji) (entries []string) {
	my_page_url := fmt.Sprintf("http://taji100.com/participants/%s/", t.participant_id)
	res, err := t.client.Get(my_page_url)
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}

	pattern := regexp.MustCompile(`<a href="/log/(.*?)/edit"><i`)
	matches := pattern.FindAllSubmatch(body, -1)
	for _, match := range matches {
		entries = append(entries, string(match[1]))
	}
	return
}

func getTajiEvents(t *taji, entries []string) (events []tajiEvent) {
	date_pattern := regexp.MustCompile(`value="(.*?)" checked`)
	time_pattern := regexp.MustCompile(`name="time" value="(.*?)"`)
	for _, entry := range entries {
		entry_url := fmt.Sprintf("http://taji100.com/log/%s/edit", entry)
		res, err := t.client.Get(entry_url)
		if err != nil {
			log.Fatal(err)
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
		}

		date := date_pattern.FindSubmatch(body)
		time := time_pattern.FindSubmatch(body)
		events = append(events, tajiEvent{date: string(date[1]), time: string(time[1])})
	}
	return
}

func createRun(date string, duration int64, distance float64) runDetails {
	t, _ := time.Parse(time.RFC3339, date)
	t = t.In(time.Local)
	seconds := duration % 60
	minutes := duration / 60
	hours := minutes / 60
	run := runDetails{
		date:             t.Format("2006-01-02"),
		time:             t.Format("03:04:PM"),
		time_hours:       t.Format("03"),
		time_minutes:     t.Format("04"),
		time_ampm:        t.Format("PM"),
		distance:         fmt.Sprintf("%1.2f", meter2mile(distance)),
		duration:         fmt.Sprintf("%01d:%01d:%02d", hours, minutes, seconds),
		duration_hours:   fmt.Sprintf("%01d", hours),
		duration_minutes: fmt.Sprintf("%01d", minutes),
		duration_seconds: fmt.Sprintf("%02d", seconds),
		duration_int:     duration,
		distance_float:   distance,
	}
	return run
}

func postRun(t *taji, r runDetails) {
	endpoint_url := "https://taji100.com/log/new?activity=run"

	res, err := t.client.Get(endpoint_url)
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}

	pattern := regexp.MustCompile(`<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' \/>`)
	match := pattern.FindSubmatch(body)
	csrfmiddlewaretoken := string(match[1]) // Get the captured group
	print(csrfmiddlewaretoken)

	values := url.Values{}
	values.Add("csrfmiddlewaretoken", csrfmiddlewaretoken)
	values.Add("activity", "run")
	values.Add("date", r.date)
	values.Add("time", r.time)
	values.Add("time_hours", r.time_hours)
	values.Add("time_minutes", r.time_minutes)
	values.Add("time_ampm", r.time_ampm)
	values.Add("distance", r.distance)
	values.Add("duration", r.duration)
	values.Add("duration_hours", r.duration_hours)
	values.Add("duration_minutes", r.duration_minutes)
	values.Add("duration_seconds", r.duration_seconds)
	values.Add("elevation_gain", r.elevation_gain)
	values.Encode()

	req, err := http.NewRequest("POST", endpoint_url, strings.NewReader(values.Encode()))
	if err != nil {
		fmt.Println(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Referer", endpoint_url)

	res, err = t.client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer res.Body.Close()

}

func meter2mile(meters float64) (miles float64) {
	miles = meters * 0.000621371
	return
}

func uploaded(run runDetails, events []tajiEvent) bool {
	target := tajiEvent{date: run.date, time: run.time}
	for _, event := range events {
		if reflect.DeepEqual(event, target) {
			return true
		}
	}
	return false
}

func updateOutput(events []tajiEvent, activities []runDetails) {
	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Run()

	miles := 0.0
	var duration int64
	duration = 0
	for _, activity := range activities {
		miles += activity.distance_float
		duration += activity.duration_int
	}
	miles = meter2mile(miles)

	fmt.Printf("Synced at %s\n", time.Now().Local())
	fmt.Printf("You have logged %d events\n", len(events))
	fmt.Printf("totaling %f miles\n", miles)
	fmt.Printf("over %d minutes.\n", duration/60)
	fmt.Printf("You are %02.2f%% of the way to completing Taji100. Great Job!\n", miles)
	fmt.Printf("Resyncing at %s.", time.Now().Local().Add(12*time.Hour))

}

func main() {
	u := new(uploader)
	initUploader(u)

	for {
		stravaActivities := getStravaActivities(&u.strava)
		entries := getTajiEntries(&u.taji)
		events := getTajiEvents(&u.taji, entries)
		for _, run := range stravaActivities {
			if !uploaded(run, events) {
				postRun(&u.taji, run)
			}
		}
		updateOutput(events, stravaActivities)
		time.Sleep(12 * time.Hour)
	}
}
