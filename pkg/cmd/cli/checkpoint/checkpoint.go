package checkpoint

import (
	"github.com/spf13/cobra"

	"github.com/vmware-tanzu/velero/pkg/client"
)

func NewCommand(f client.Factory) *cobra.Command {
	c := &cobra.Command{
		Use:   "checkpoint",
		Short: "Work with checkpoint",
		Long:  "Work with backups",
	}

	c.AddCommand(
		NewCreateCommand(f, "create"),
		/* NewGetCommand(f, "get"),
		NewLogsCommand(f),
		NewDescribeCommand(f, "describe"),
		NewDownloadCommand(f),
		NewDeleteCommand(f, "delete"),*/
	)

	return c
}
