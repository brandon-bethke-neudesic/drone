package timu

import (
	"net"
	"net/http"
	"net/url"
	"github.com/drone/drone/model"
    "io/ioutil"
    "encoding/json"
    "strings"
    "strconv"
    "errors"

	log "github.com/Sirupsen/logrus"

)

type JsonData map[string]interface{}

type Timu struct {
	URL         string
	API         string
	Client      string
	Secret      string
	Scope       string
	MergeRef    string
	Orgs        []string
	Open        bool
	PrivateMode bool
	SkipVerify  bool
	AccessToken string
	Network string
	Subdomain string
}

func (t *Timu) CompressNounType(nounType string) (string) {
	if nounType == "core:project" {
		return ""
	} else if nounType == "core:code-module" {
		return ""		
	} else if nounType == "core:project-module"{
		return ""
	} else {
		return nounType;
	}
}

func (t *Timu) ExpandNounType(nounType string) (string) {
	if nounType == "p" {
		return "core:project"
	} else if nounType == "library" {
		return "core:code-module"
	} else {
		return nounType;
	}	
}

func Load(config string) *Timu {
	log.Debugf("Timu Load Called")
	// parse the remote DSN configuration string
	url_, err := url.Parse(config)
	if err != nil {
		log.Fatalln("unable to parse remote dsn. %s", err)
	}
	params := url_.Query()
	url_.Path = ""
	url_.RawQuery = ""

	t := Timu{}
	t.Subdomain = params.Get("subdomain")
	t.URL = strings.Replace(url_.String(), "://api.", "://" + t.Subdomain + ".", 1)
	t.API = url_.String();
	t.Client = params.Get("client_id")
	t.Secret = params.Get("client_secret")
	t.Orgs = params["orgs"]
	t.Open, _ = strconv.ParseBool(params.Get("open"))
	t.AccessToken = params.Get("access_token")
	t.Network = params.Get("$network")
	t.SkipVerify, _ = strconv.ParseBool(params.Get("skip_verify"))

	return &t
}

// Login authenticates the session and returns the
// remote user details.
func (t *Timu) Login(w http.ResponseWriter, r *http.Request) (*model.User, bool, error) {
	log.Debugf("Timu Login Called")

	timuClient := &TimuClient{ Insecure: t.SkipVerify, AccessToken: t.AccessToken };

	var url = t.API + "/api/graph/me?$network=" + t.Network
	log.Debugf("URL: " + url)
	jsondata, err := timuClient.Get(url);
	if err != nil {
		return nil, true, err;
	}
	user := &model.User{}	
	user.Email = jsondata["email"].(string)
	if jsondata["name"] == nil {
		user.Login = user.Email; 
	} else {
		user.Login = jsondata["name"].(string)		
	}
	user.Token = t.AccessToken
	user.Secret = t.AccessToken
	return user, t.Open, nil
}

// Auth authenticates the session and returns the remote user
// login for the given token and secret
func (t *Timu) Auth(token, secret string) (string, error) {
	log.Debugf("Timu Auth Called")	
	timuClient := &TimuClient{ Insecure: t.SkipVerify, AccessToken: t.AccessToken  };
	var url = t.API + "/api/graph/me?$network=" + t.Network
	jsondata, err := timuClient.Get(url);
	if err != nil {
		return "", err;
	}

	return jsondata["name"].(string), nil
}

func (t *Timu) String() string {
	return "timu"
}

// Repo fetches the named repository from the remote system.
func (t *Timu) Repo(u *model.User, owner string, reponame string) (*model.Repo, error) {
	log.Debugf("Timu Repo Called " + reponame)
	adjustedName := strings.Replace(reponame, ">", "/", -1)
	repo := &model.Repo{}
	repo.Owner = "timu"
	repo.Name = reponame
	repo.FullName = "timu/" + reponame
	repo.Link = t.URL + "/" + adjustedName
	repo.Clone = t.URL + "/" + adjustedName + ".git"
	repo.Branch = "master"
	repo.IsPrivate = true	
	return repo, nil
}

func (t *Timu) getLibraryPath(dataItem map[string]interface{}, references map[string]interface{}, useId bool) (string) {
	var name = strconv.FormatFloat(dataItem["id"].(float64), 'f', -1, 64);
	keyItem := dataItem["key"]
	if !useId && keyItem != nil {
		temp := dataItem["key"].(string)
		if len(temp) > 0 {
			name = temp;
		}
	}

	nounType := dataItem["type"].(string)
	nounType = t.CompressNounType(nounType)

	finalName := ""

	if len(nounType) > 0 {
		finalName = nounType + "/" + name	
	} else {
		finalName = name;
	}

	container := dataItem["container"].(string);
	atRoot := false
	for !atRoot {
		parentContainer := references[container].(map[string]interface{})

		if parentContainer["type"].(string) == "core:project-module" && 
			references[parentContainer["container"].(string)].(map[string]interface{})["type"].(string) == "core:network" {
				atRoot = true;
		} else {
			containerItem := references[container].(map[string]interface{});
        	var containerName = strconv.FormatFloat(containerItem["id"].(float64), 'f', -1, 64);
        	containerItemKey := containerItem["key"];
        	if containerItemKey != nil {
        		temp := containerItemKey.(string)
        		if len(temp) > 0 {
	        		containerName = temp			        			
        		}
        	}
        	nounType = containerItem["type"].(string)
        	nounType = t.CompressNounType(nounType)
        	if len(nounType) > 0 {
        		finalName = nounType + "/" + containerName + "/" + finalName
        	} else {
        		finalName = containerName + "/" + finalName
        	}
        	container = containerItem["container"].(string)
		}

	}
	
	// Encode the name
	finalName = strings.Replace("projects/" + finalName, "/", ">", -1)
	return finalName
}

// Repos fetches a list of repos from the remote system.
func (t *Timu) Repos(u *model.User) ([]*model.RepoLite, error) {
	log.Debugf("Timu Repos Called")
	var repos []*model.RepoLite
	var url = t.API + "/api/graph/core:code-module?size=25&$network=" + t.Network
	log.Debugf("Getting repos at " + url)
    var paging = true;
	timuClient := &TimuClient{ Insecure: t.SkipVerify, AccessToken: t.AccessToken  };

    for paging {

		jsondata, err := timuClient.Get(url);
		if err != nil {
			return repos, err;
		}
	    pagingSection := jsondata["paging"].(map[string]interface{})
	    if pagingSection["next"] != nil {
	    	url = t.API + pagingSection["next"].(string) + "&$network=" + t.Network
	    	log.Infof(url)
	    	paging = true
	    } else {
	    	paging = false;
	    }

	    var finalName = "";
	    dataSection := jsondata["data"].([]interface{});
	    references := jsondata["references"].(map[string]interface{})
	    dataSectionLength := len(dataSection);
	    log.Debugf("Found " + strconv.Itoa(dataSectionLength) + " code libraries")
	    for i := 0; i < dataSectionLength; i++ {
	        dataItem := dataSection[i].(map[string]interface{})
	        log.Debugf("Getting path for library " + dataItem["url"].(string))	        
        	finalName = t.getLibraryPath(dataItem, references, false)        	
			repos = append(repos, &model.RepoLite{
				Owner:    "timu",
				Name:     finalName,
				FullName: "timu/" + finalName,
			})
	    }
    }

    return repos, nil
}

// Perm fetches the named repository permissions from
// the remote system for the specified user.
func (t *Timu) Perm(u *model.User, owner string, reponame string) (*model.Perm, error) {
	log.Debugf("Timu Perm Called " + reponame)
	perms := new(model.Perm)
	perms.Pull = true
	perms.Push = true
	perms.Admin = true

	return perms, nil
}

func (t *Timu) getLibraryFromId(libraryId string) (map[string]interface{}, error) {
	var url = t.API + "/api/graph/core:code-module/" + libraryId + "?network=" + t.Network
	log.Printf(url)	
	timuClient := &TimuClient{ Insecure: t.SkipVerify, AccessToken: t.AccessToken  };
	jsondata, err := timuClient.Get(url);
	if err != nil {
		return nil, err;
	}

    return jsondata, nil
}

func (t *Timu) getLibraryFromName(name string) (map[string]interface{}, error) {
	paths := strings.SplitN(name, ">", -1);
	// The last part of the name is the library key
	libraryKey := paths[len(paths) - 1];
	// If the library key is a number, then most likely the key is actually the library id.
	_, err := strconv.ParseFloat(libraryKey, 64);
	if err == nil {
		return t.getLibraryFromId(libraryKey)
	} else {
		// Get all libraries with the key of libraryKey and determine which library is actually the library we want.
		var url = t.API + "/api/graph/core:code-module?$key=" + libraryKey + "&size=25&$network=" + t.Network
		log.Printf(url)	
	    var paging = true;
	    var done = false;
	    var result map[string]interface{} = nil;
		timuClient := &TimuClient{ Insecure: true, AccessToken: t.AccessToken  };

	    for paging && !done {

			jsondata, err := timuClient.Get(url);
			if err != nil {
				return nil, err;
			}

		    // If there is a next page, make sure to save it in case we need don't find the library in this page.
		    pagingSection := jsondata["paging"].(map[string]interface{})
		    if pagingSection["next"] != nil {
		    	url = t.API + pagingSection["next"].(string) + "&$network=" + t.Network
		    	paging = true
		    } else {
		    	paging = false;
		    }

		    var finalName = "";
		    dataSection := jsondata["data"].([]interface{});
		    references := jsondata["references"].(map[string]interface{})
		    // For each library item, compare the names
		    for i := 0; i < len(dataSection) && !done; i++ {
		        dataItem := dataSection[i].(map[string]interface{})	        
	        	finalName = t.getLibraryPath(dataItem, references, false)
	        	log.Debugf(name + " " + finalName)
	        	if strings.Compare(name, finalName) == 0 {
	        		// If the names match, then this is the library we want
	        		result = dataItem;
	        		result["references"] = references;
	        		done = true;
	        	}
		    }
		}

		if !done {
			return nil, errors.New("Could not find the library")
		}	

		return result, nil;
	}
}

// File fetches a file from the remote repository and returns in string format.
func (t *Timu) File(user *model.User, repo *model.Repo, b *model.Build, filename string) ([]byte, error) {
	log.Debugf("Timu File Called " + filename)
	// We need the library id to call the files api.
	library, err := t.getLibraryFromName(repo.Name);
    if err != nil {
        return nil, err;
    }
	timuClient := &TimuClient{ Insecure: t.SkipVerify, AccessToken: t.AccessToken  };

	libId := strconv.FormatFloat(library["id"].(float64), 'f', -1, 64)
	log.Debugf("Using library id " + libId + " for " + repo.Name)
    url :=  t.API + "/api/g/files/" + libId + "/blobs/commits/" + b.Commit + "/" + filename + "?$network=" + t.Network;
    log.Debugf(url)

	body, err := timuClient.GetFile(url);
	if err != nil {
		return nil, err;
	}

	return body, nil
}

// Status sends the commit status to the remote system.
// An example would be the GitHub pull request status.
func (t *Timu) Status(u *model.User, r *model.Repo, b *model.Build, link string) error {
	log.Debugf("Timu Status Called " + link)

	return nil
}

// Netrc returns a .netrc file that can be used to clone
// private repositories from a remote system.
func (t *Timu) Netrc(u *model.User, r *model.Repo) (*model.Netrc, error) {
	log.Debugf("Timu Netrc Called ")

	netrc := &model.Netrc{}
	netrc.Login = u.Token
	netrc.Password = u.Token
	url, _ := url.Parse(t.URL);
	host := url.Host;
	// Don't need the port
	if strings.Contains(url.Host, ":") {
		host, _, _ = net.SplitHostPort(url.Host)
	}
	netrc.Machine =  host;
	log.Debugf("Allowing host " + netrc.Machine)
	return netrc, nil
}

// Activate activates a repository by creating the post-commit hook and
// adding the SSH deploy key, if applicable.
func (t *Timu) Activate(u *model.User, repo *model.Repo, k *model.Key, link string) error {
	log.Debugf("Timu Activate Called " + link)
	libraryData, err := t.getLibraryFromName(repo.Name);
	if err != nil {
		return err
	}

	libraryId := strconv.FormatFloat(libraryData["id"].(float64), 'f', -1, 64)
	var hooksSection []interface{} = nil;
	if libraryData["webhooks"] == nil {
		hooksSection = make([]interface{}, 0)
	} else {
		hooksSection = libraryData["webhooks"].([]interface{})
	}

	hooksSectionLength := len(hooksSection)
	alreadyActivated := false
	parsedLink, _ := url.Parse(link);
    for i := 0; i < hooksSectionLength && !alreadyActivated; i++ {
    	existingHook := hooksSection[i].(map[string]interface{});
    	parsedExistingHook, _ := url.Parse(existingHook["url"].(string));
    	url1 := strings.ToLower(parsedLink.Host)
    	url2 := strings.ToLower(parsedExistingHook.Host)
    	if strings.Compare(url1, url2) == 0 {
    		alreadyActivated = true
    	}
	}
	if alreadyActivated {
		return nil;
	}

	hook := map[string]interface{}{};
	events := make([]string, 0);
	events = append(events, "push")
	hook["events"] = events;
	hook["url"] = link;
	hooksSection = append(hooksSection, hook)
	hooks := map[string]interface{}{};
	hooks["webhooks"] = hooksSection;
    content, _ := json.Marshal(hooks)
    log.Debugf("Adding Hook " + link)

	timuClient := &TimuClient{ Insecure: t.SkipVerify, AccessToken: t.AccessToken  };

	url := t.API + "/api/graph/core:code-module/" + libraryId + "?network=" + t.Network;

	_, err = timuClient.Post(url, content);
	if err != nil {
		return err;
	}

	return nil	
}

// Deactivate removes a repository by removing all the post-commit hooks
// which are equal to link and removing the SSH deploy key.
func (t *Timu) Deactivate(u *model.User, repo *model.Repo, link string) error {
	log.Debugf("Timu Deactivate Called " + link)
	libraryData, err := t.getLibraryFromName(repo.Name);
	if err != nil {
		return err
	}
	// If the hooks section is empty, then there is nothing to remove.
	if libraryData["webhooks"] == nil {
		return nil;
	} 

	libraryId := strconv.FormatFloat(libraryData["id"].(float64), 'f', -1, 64)

	var newHooks = make([]interface{}, 0);
	hooksSection := libraryData["webhooks"].([]interface{})
	hooksSectionLength := len(hooksSection)
	removedItems := false
	parsedLink, _ := url.Parse(link);
    for i := 0; i < hooksSectionLength; i++ {
    	existingHook := hooksSection[i].(map[string]interface{});
    	parsedExistingHook, _ := url.Parse(existingHook["url"].(string));
    	url1 := strings.ToLower(parsedLink.Host)
    	url2 := strings.ToLower(parsedExistingHook.Host)
    	if strings.Compare(url1, url2) != 0 {
    		newHooks = append(newHooks, existingHook);
    	} else {
    		removedItems = true;    		
    	}
	}
	// If nothing was removed then we don't need to update the hooks.
	if !removedItems {
		return nil;
	}
	hooks := map[string]interface{}{};
	hooks["webhooks"] = newHooks;
    content, _ := json.Marshal(hooks)
    log.Debugf("Deleting Hook " + link)
	timuClient := &TimuClient{ Insecure: t.SkipVerify, AccessToken: t.AccessToken  };
	url := t.API + "/api/graph/core:code-module/" + libraryId + "?network=" + t.Network;
	_, err = timuClient.Post(url, content);
	if err != nil {
		return err;
	}
	return nil
}

// Hook parses the commit information from the Request body
// and returns the required data in a standard format.
func (t *Timu) Hook(req *http.Request) (*model.Repo, *model.Build, error) {
	log.Debugf("Timu Hook Called")

	defer req.Body.Close()
	var body, _ = ioutil.ReadAll(req.Body)
    var jsondata JsonData;
    err := json.Unmarshal(body, &jsondata);
    if err != nil {
        return nil, nil, err
    }

    log.Debugf(string(body))


    after := jsondata["after"].(string)
    ref := jsondata["ref"].(string);
    message := jsondata["head_commit"].(map[string]interface{})["message"].(string)
	branch := strings.TrimPrefix(ref, "refs/heads/")  

	tempId := jsondata["repository"].(map[string]interface{})["id"].(float64) 
	libraryId := strconv.FormatFloat(tempId, 'f', -1, 64)
	library, err := t.getLibraryFromId(libraryId);
    if err != nil {
        return nil, nil, err
    }
	references := library["references"];
	libraryPath := t.getLibraryPath(library, references.(map[string]interface{}), false)
	reponame := libraryPath;
	adjustedName := strings.Replace(reponame, ">", "/", -1)
	clone := t.URL + "/" + adjustedName

	repo := &model.Repo{}
	repo.Owner = "timu"
	repo.Name = reponame
	repo.FullName = "timu/" + reponame
	repo.Link = clone
	repo.Clone = clone + ".git"
	repo.Branch = "master"
	repo.IsPrivate = true	

	build := &model.Build{}
	build.Event = model.EventPush
	build.Commit = after
	build.Branch = branch
	build.Ref = ref

	build.Message = message;

	return repo, build, nil
}
