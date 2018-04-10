package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/spf13/cobra"
)

var (
	regions []string
	client  *http.Client
)

// pushCmd represents the push command
var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push a dashboard directory into multiple Kibana instances",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("must specify dashboard root path")
		}

		fi, err := os.Stat(args[0])
		if err != nil {
			return fmt.Errorf("could not get path information: %v", err)
		}

		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", args[0])
		}

		return nil
	},
	RunE: pushRun,
}

func init() {
	rootCmd.AddCommand(pushCmd)

	pushCmd.Flags().StringSliceVar(&regions, "regions", nil, "List of regions to push (default to all regions)")

	client = &http.Client{}
}

func checkRegions(regions []string) ([]string, error) {
	partition := endpoints.AwsPartition()
	ec2regions, found := partition.RegionsForService(endpoints.Ec2ServiceID)
	if !found {
		return nil, fmt.Errorf("missing regions for service %s", endpoints.Ec2ServiceID)
	}

	// If no regions specified, run on all regions
	if regions == nil {
		r := make([]string, 0, len(ec2regions))
		for k := range ec2regions {
			r = append(r, k)
		}
		return r, nil
	}

	invalid := make([]string, 0, 0)
	for _, region := range regions {
		if _, ok := ec2regions[region]; !ok {
			invalid = append(invalid, region)
		}
	}

	if len(invalid) == 0 {
		return regions, nil
	}

	return nil, errors.New(strings.Join(invalid, ", "))
}

func loadDashboards(root string, recursive bool) ([][]byte, error) {
	dashboards := make([][]byte, 0, 0)
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsDir() {
			return nil
		}

		d, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		dashboards = append(dashboards, d)

		return nil
	}); err != nil {
		return nil, err
	}

	return dashboards, nil
}

func pushRun(cmd *cobra.Command, args []string) error {
	regions, err := checkRegions(regions)
	if err != nil {
		return fmt.Errorf("invalid regions: %v", err)
	}

	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return fmt.Errorf("unable to load AWS config: %v", err)
	}

	dashboards, err := loadDashboards(args[0], true)
	if err != nil {
		return fmt.Errorf("could not load dashboards: %v", err)
	}

	return pushRegions(dashboards, cfg, regions)
}

// pushRegions iterates on each region given, listing all EC2 instances with a specific tag
// and posting registered dashboards into the Kibana instance
func pushRegions(dashboards [][]byte, cfg aws.Config, regions []string) error {
	var wg sync.WaitGroup
	for _, region := range regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			pushRegion(dashboards, cfg, region)
		}(region)
	}

	wg.Wait()

	return nil
}

func pushRegion(dashboards [][]byte, cfg aws.Config, region string) error {
	cfg.Region = region

	targetIps := make([]string, 0, 0)

	svc := ec2.New(cfg)
	req := svc.DescribeInstancesRequest(&ec2.DescribeInstancesInput{
		Filters: []ec2.Filter{
			ec2.Filter{
				Name: aws.String("tag:Role"),
				Values: []string{
					"kibana",
				},
			},
		},
	})

	// no DescribeInstancePages in v2 yet
	p := req.Paginate()
	for p.Next() {
		page := p.CurrentPage()

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				ip := *instance.PrivateIpAddress
				for _, ni := range instance.NetworkInterfaces {
					if ni.PrivateIpAddress != nil {
						targetIps = append(targetIps, *ni.PrivateIpAddress)
						if ip != *ni.PrivateIpAddress {
							panic("different ip")
						}

						break
					}
				}
			}
		}
	}
	if err := p.Err(); err != nil {
		return fmt.Errorf("could not fetch instances: %v", err)
	}

	if len(targetIps) == 0 {
		// no matching instance is OK
		return nil
	}

	var wg sync.WaitGroup
	for _, ip := range targetIps {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			pushKibana(dashboards, ip)
		}(ip)
	}

	wg.Wait()

	return nil
}

func pushKibana(dashboards [][]byte, ip string) error {
	fmt.Println(ip)

	for _, dashboard := range dashboards {
		req, err := http.NewRequest(
			"POST",
			fmt.Sprintf("http://%s:5601/api/kibana/dashboards/import?force=true", ip),
			bytes.NewBuffer(dashboard),
		)
		if err != nil {
			return fmt.Errorf("could not create request: %v", err)
		}

		req.Header.Set("kbn-xsrf", "anything")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("could not upload: %v", err)
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("invalid body: %v", err)
		}

		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("failed upload (%d): %s", resp.StatusCode, body)
		}
	}

	return nil
}
