package timu

import (

	"net/http"
    "crypto/tls"
    "io/ioutil"
    "encoding/json"
    "errors"
    "strconv"
    "bytes"
)


type TimuClient struct {
	Insecure bool
	AccessToken string
}


func (t *TimuClient) Post(url string, content []byte) (JsonData, error) {
    client := t.GetHttpClient(t.Insecure);
    request := t.GetNewRequest("POST", url, t.AccessToken, content)
	request.Header.Set("Content-Type", "application/json");
    response, err := client.Do(request)    
    if err != nil {
        return nil, err;
    }
    defer response.Body.Close()
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return nil, err
    }        

    var jsondata JsonData;
    if len(body) > 0 {
	    err = json.Unmarshal(body, &jsondata);
	    if err != nil {
	        return nil, err
	    }    	
    }

    if response.StatusCode >= 400 {
		return jsondata, errors.New("Error. Status Code: " + strconv.Itoa(response.StatusCode) + ". " + string(body));     	
    }
    return jsondata, nil
}

func (t *TimuClient) Get(url string) (JsonData, error) {
    client := t.GetHttpClient(t.Insecure);
	request := t.GetNewRequest("GET", url, t.AccessToken, nil)    
    var response, err = client.Do(request)
    if err != nil {
        return nil, err;
    }
    defer response.Body.Close();
    body, err := ioutil.ReadAll(response.Body)
    var jsondata JsonData;
    if len(body) > 0 {
	    err = json.Unmarshal(body, &jsondata);
	    if err != nil {
	        return nil, err
	    }
	}

    if response.StatusCode >= 400 {
		return jsondata, errors.New("Error. Status Code: " + strconv.Itoa(response.StatusCode) + ". " + string(body));     	
    }

    return jsondata, nil;
}

func (t *TimuClient) GetFile (url string) ([]byte, error) {
    client := t.GetHttpClient(t.Insecure);
    request := t.GetNewRequest("GET", url, t.AccessToken, nil);
    var response, err = client.Do(request)
    if err != nil {
        return nil, err;
    }
    defer response.Body.Close();
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return nil, err
    }
    if response.StatusCode >= 400 {
		return nil, errors.New("There was a problem retreiving the file. Status Code: " + strconv.Itoa(response.StatusCode) + ". " + string(body));     	
    }

    return body, nil;
}

func (t *TimuClient) GetNewRequest(method string, url string, token string, content []byte)(*http.Request) {
    request, _ := http.NewRequest(method, url, bytes.NewBuffer(content))
    if len(token) > 0 {    	
    	request.Header.Set("Authorization", "Bearer " + token)
	}	
	return request;
}

func (t *TimuClient) GetHttpClient(insecure bool)(*http.Client){
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
    }
    client := &http.Client{Transport: tr}
    return client
}