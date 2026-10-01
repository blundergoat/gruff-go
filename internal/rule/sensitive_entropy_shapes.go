// Package rule defines gruff-go's rule registry and analysers.
//
// These checks keep recognizable public constants out of the user's entropy warnings.
// Every part of a value must qualify; readable names cannot hide an opaque suffix.
package rule

import (
	"regexp"
	"strings"
)

// Compare complete public alphabets so appending opaque text cannot inherit their exception.
var entropyPublicAlphabets = map[string]bool{
	"abcdefghijklmnopqrstuvwxyz0123456789":                              true,
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":    true,
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_":  true,
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":    true,
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":    true,
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":                              true,
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_":   true,
	"abcdefghijklmnopqrstuvwxyz0123456789-_":                            true,
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/":  true,
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=": true,
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_":  true,
	"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789":           true,
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890":    true,
}

var (
	// entropyPublicFormat recognizes two complete public vendor formats.
	entropyPublicFormat = regexp.MustCompile(`^(?:[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com|soljson-v[0-9]+\.[0-9]+\.[0-9]+\+commit\.[0-9a-f]{8}\.js)$`)
	// entropyNameShape requires complete ASCII name segments.
	entropyNameShape = regexp.MustCompile(`^[A-Za-z0-9]+(?:[/._-]+[A-Za-z0-9]+)+$`)
	// entropyNameSeparators splits runs of the approved separators.
	entropyNameSeparators = regexp.MustCompile(`[/._-]+`)
	// entropyNameRuns consumes each letter or digit run.
	entropyNameRuns = regexp.MustCompile(`[A-Za-z]+|[0-9]+`)
	// entropyWordCase rejects arbitrary short case switches.
	entropyWordCase = regexp.MustCompile(`^(?:[A-Z]*[a-z]+|[A-Z]+|(?:[a-z]{3,}|[A-Z]{3,}|[A-Z][a-z]{2,})(?:[A-Z][a-z]{2,}|[A-Z]{3,})+)$`)
	// entropyShortCode recognizes the finite bounded code and timestamp forms.
	entropyShortCode = regexp.MustCompile(`^(?:[vVxXrR][0-9]{1,4}|[0-9]{1,4}[bBeE]|[aA][0-9]{1,4}[bB]|FP[0-9]{1,4}|i18n|ec2|[mMtT][0-9]{2,3}|[0-9]{8}T[0-9]{4}(?:[0-9]{2})?Z)$`)
)

// isPublicEntropyShape checks a complete literal before the scanner raises an entropy warning.
// Empty content matches no exception; an accepted shape is a precision heuristic, not proof that the value is public.
func isPublicEntropyShape(value string) bool {
	return entropyEntraApplicationURL.MatchString(value) || entropySignatureServiceID.MatchString(value) || entropyGitHubCommitURL.MatchString(value) || entropyPublicAlphabets[value] || entropyPublicFormat.MatchString(value) || isBoundedPublicEntropyFormat(value) || isStructuredEntropyName(value)
}

var (
	// entropyEntraApplicationURL accepts only the complete portal route with a public application identifier and fixed navigation flags.
	entropyEntraApplicationURL = regexp.MustCompile(`^https://entra\.microsoft\.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/isMSAApp~/false\?Microsoft_AAD_IAM_legacyAADRedirect=true$`)
	// entropySignatureServiceID names the nine observed container services; extra text cannot inherit their exception.
	entropySignatureServiceID = regexp.MustCompile(`^security\.access_token_handler\.oidc\.signature\.(?:ES|RS|PS)(?:256|384|512)$`)
	// entropyGitHubCommitURL recognizes a complete public revision reference without credentials or extra URL components.
	entropyGitHubCommitURL = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9][A-Za-z0-9._-]{0,99}/commit/[0-9a-f]{40}$`)
	// entropyHelpArticleURL requires a complete public route with no credentials, query or fragment.
	entropyHelpArticleURL = regexp.MustCompile(`^https://support\.halaxy\.com/hc/[a-z]{2}-[a-z]{2}/articles/[0-9]{12,13}-([A-Za-z]+(?:-[A-Za-z]+)*)$`)
	// entropyHelpArticlePath keeps a stored help link's relative route subject to the same title bounds.
	entropyHelpArticlePath = regexp.MustCompile(`^/hc/[a-z]{2}-[a-z]{2}/articles/[0-9]{12,13}-([A-Za-z]+(?:-[A-Za-z]+)*)$`)
	// entropyQueueURL accepts only a regional SQS endpoint and the observed non-authentication query option.
	entropyQueueURL = regexp.MustCompile(`^https://sqs\.[a-z]{2}(?:-[a-z]{3,16}){1,2}-[1-9]\.amazonaws\.com/[0-9]{12}/([A-Za-z0-9_-]+)(?:\?auto_setup=false)?$`)
)

// isPublicEntropyURL checks the complete endpoint before token scanning splits its punctuation.
// Unknown URL components grant no exception, even when the hostname looks public.
func isPublicEntropyURL(completeURL string) bool {
	// A complete revision or portal reference identifies public metadata without carrying authentication material.
	if entropyGitHubCommitURL.MatchString(completeURL) || entropyEntraApplicationURL.MatchString(completeURL) {
		return true
	}
	// A help link's article label must contain only bounded words or the approved short joiners.
	if article := entropyHelpArticleURL.FindStringSubmatch(completeURL); article != nil {
		return isPublicEntropyArticleLabel(article[1])
	}
	queue := entropyQueueURL.FindStringSubmatch(completeURL)
	return queue != nil && isStructuredEntropyName(queue[1])
}

// isPublicEntropyArticleLabel checks every title word before a complete article URL or route may skip scoring.
// Empty labels fail; only the approved short joiners can fall below the usual word length.
func isPublicEntropyArticleLabel(label string) bool {
	// A readable title cannot vouch for an unrelated opaque suffix.
	for _, word := range strings.Split(label, "-") {
		// Only the observed joiners "a", "to" and "in" may be shorter than an ordinary title word.
		if word != "a" && word != "to" && word != "in" && (len(word) < 3 || len(word) > 32 || !entropyWordCase.MatchString(word)) {
			return false
		}
	}
	return true
}

// isStructuredEntropyName recognizes readable names and repository paths without letting their words hide an opaque tail.
// At least two word segments must supply a strict letter majority; empty or malformed names remain eligible for scoring.
func isStructuredEntropyName(value string) bool {
	// A committed path may start with two parent components or one rooted, hidden or current-directory prefix.
	for _, prefix := range []string{"../../", "../", "./", "/", "."} {
		// Stopping at the first prefix keeps repeated leading dots or slashes outside the exception.
		if strings.HasPrefix(value, prefix) {
			value = strings.TrimPrefix(value, prefix)
			break
		}
	}
	// Missing segments or other punctuation keep the value eligible for a warning.
	if !entropyNameShape.MatchString(value) {
		return false
	}
	alphanumericCount, wordLetterCount, wordSegmentCount := 0, 0, 0
	// Readable directories do not excuse a random-looking filename; check each part independently.
	for _, segment := range entropyNameSeparators.Split(value, -1) {
		letters, valid := entropySegmentWordLetters(segment)
		// A rejected segment prevents the whole value from receiving the public-name exception.
		if !valid {
			return false
		}
		alphanumericCount += len(segment)
		wordLetterCount += letters
		// Codes and short labels cannot supply either of the two word-bearing segments needed to skip a warning.
		if letters > 0 {
			wordSegmentCount++
		}
	}
	return wordSegmentCount >= 2 && wordLetterCount*2 > alphanumericCount
}

// entropySegmentWordLetters counts readable word letters without accepting an opaque suffix in the same populated ASCII segment.
// A zero count supplies no word evidence; a false validity result rejects the whole name.
func entropySegmentWordLetters(segment string) (int, bool) {
	// Long undivided segments can hold opaque values, so they remain eligible for a warning.
	if len(segment) > 32 {
		return 0, false
	}
	// Model codes and timestamps may occur in public paths but contribute no readable-word evidence.
	if entropyShortCode.MatchString(segment) {
		return 0, true
	}
	runs := entropyNameRuns.FindAllString(segment, -1)
	wordLetterCount, digitRuns := 0, 0
	// Inspect every run so a readable opening cannot hide later random-looking text.
	for _, run := range runs {
		// Numeric parts have tighter bounds when mixed with words, preserving warnings on opaque identifiers.
		if run[0] >= '0' && run[0] <= '9' {
			digitRuns++
			limit := 4
			// A standalone short number can label a version or path part without pretending to be a word.
			if len(runs) == 1 {
				limit = 6
			}
			// Repeated or long number runs prevent the name from receiving an exception.
			if len(run) > limit || digitRuns > 2 {
				return 0, false
			}
		} else {
			// Arbitrary case changes or short interleaved letters do not establish a readable public name.
			if !entropyWordCase.MatchString(run) || (len(runs) > 1 && len(run) < 3) {
				return 0, false
			}
			// Short labels may occur in names but cannot supply the word majority needed to skip a warning.
			if len(run) >= 3 {
				wordLetterCount += len(run)
			}
		}
	}
	return wordLetterCount, true
}

// entropyDetailFormats capture the word portion of established help routes and clinical identifiers.
var entropyDetailFormats = []*regexp.Regexp{
	regexp.MustCompile(`^/hc/[a-z]{2}-[a-z]{2}/(?:sections|categories)/[0-9]{12}-([A-Za-z]+(?:-[A-Za-z]+)*)$`),
	regexp.MustCompile(`^(?:PH|PHVS)_([A-Za-z]+)_HL7_V[0-9]{1,4}$`),
}

// isBoundedPublicEntropyFormat keeps established help routes and clinical codes quiet only when every word fits their format.
// An unmatched or malformed value stays eligible for entropy scoring.
func isBoundedPublicEntropyFormat(candidate string) bool {
	// A stored relative help link uses the article-only title grammar after its complete route matches.
	if article := entropyHelpArticlePath.FindStringSubmatch(candidate); article != nil {
		return isPublicEntropyArticleLabel(article[1])
	}
	// Either recognized format must account for the complete literal the user committed.
	for _, pattern := range entropyDetailFormats {
		match := pattern.FindStringSubmatch(candidate)
		// An unmatched format grants no exemption; the next known format may still fit.
		if match == nil {
			continue
		}
		// Every route label or clinical name must be readable, even after a recognized public prefix.
		for _, word := range strings.Split(match[1], "-") {
			// An opaque label leaves the whole value eligible for a warning.
			if len(word) < 3 || len(word) > 32 || !entropyWordCase.MatchString(word) {
				return false
			}
		}
		return true
	}
	return false
}
