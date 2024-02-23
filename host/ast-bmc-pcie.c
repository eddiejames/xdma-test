// SPDX-License-Identifier: GPL-2.0

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uaccess.h>

#define DRIVER_NAME			"ast-bmc"
#define BUF_SIZE			16777216

#define PCI_VENDOR_ID_ASPEED		0x1a03
#define PCI_DEVICE_ID_AST2500_VGA	0x2000

struct ast_bmc_addr {
	dma_addr_t dma;
	void *virt;
};

struct ast_bmc {
	struct ast_bmc_addr mem;
	struct miscdevice misc;
};

#define misc2ast_bmc(x) container_of((x), struct ast_bmc, misc)

static loff_t ast_bmc_pci_seek(struct file *file, loff_t offset, int whence)
{
	switch (whence) {
	case SEEK_CUR:
		break;
	case SEEK_SET:
		file->f_pos = offset;
		break;
	default:
		return -EINVAL;
	}

	return offset;
}

static ssize_t ast_bmc_pci_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
	int rc;
	struct miscdevice *misc = file->private_data;
	struct ast_bmc *ctx = misc2ast_bmc(misc);
	loff_t offs = *offset;

	if (len + offs > BUF_SIZE)
		return -EINVAL;

	rc = copy_to_user(buf, ctx->mem.virt + offs, len);
	if (rc)
		return rc;

	*offset += len;

	return len;
}

static ssize_t ast_bmc_pci_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
	int rc;
	struct miscdevice *misc = file->private_data;
	struct ast_bmc *ctx = misc2ast_bmc(misc);
	loff_t offs = *offset;

	if (len + offs > BUF_SIZE)
		return -EINVAL;

	rc = copy_from_user(ctx->mem.virt + offs, buf, len);
	if (rc)
		return rc;

	*offset += len;

	return len;
}

static const struct file_operations ast_bmc_pci_fops = {
	.owner	= THIS_MODULE,
	.llseek	= ast_bmc_pci_seek,
	.read	= ast_bmc_pci_read,
	.write	= ast_bmc_pci_write,
};

static int ast_bmc_pci_probe(struct pci_dev *pdev,
			     const struct pci_device_id *ent)
{
	int rc;
	struct ast_bmc *ctx = devm_kzalloc(&pdev->dev, sizeof(*ctx),
					   GFP_KERNEL);

	if (!ctx) {
		dev_err(&pdev->dev, "Failed to allocate context structure\n");
		return -ENOMEM;
	}

	rc = pci_enable_device(pdev);
	if (rc) {
		dev_err(&pdev->dev, "Failed to enable AST BMC device\n");
		return rc;
	}

	pci_set_master(pdev);

	dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));

	dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));

	ctx->mem.virt = dma_alloc_coherent(&pdev->dev, BUF_SIZE,
					   &ctx->mem.dma, GFP_KERNEL);
	if (!ctx->mem.virt) {
		dev_err(&pdev->dev, "Failed to allocate DMA\n");
		pci_clear_master(pdev);
		pci_disable_device(pdev);
		return -ENOMEM;
	}

	pci_set_drvdata(pdev, ctx);

	dev_info(&pdev->dev, "PCI DMA addr: %016llx\n", ctx->mem.dma);

	ctx->misc.minor = MISC_DYNAMIC_MINOR;
	ctx->misc.fops = &ast_bmc_pci_fops;
	ctx->misc.name = "ast-bmc-mem";
	ctx->misc.parent = &pdev->dev;
	rc = misc_register(&ctx->misc);
	if (rc) {
		dev_err(&pdev->dev, "Unable to register AST BMC miscdevice\n");
		dma_free_coherent(&pdev->dev, BUF_SIZE, ctx->mem.virt, ctx->mem.dma);
		pci_clear_master(pdev);
		pci_disable_device(pdev);
		return rc;
	}

	return 0;
}

static void ast_bmc_pci_remove(struct pci_dev *pdev)
{
	struct ast_bmc *ctx = pci_get_drvdata(pdev);

	misc_deregister(&ctx->misc);

	dma_free_coherent(&pdev->dev, BUF_SIZE, ctx->mem.virt, ctx->mem.dma);

	pci_clear_master(pdev);

	pci_disable_device(pdev);
}

static const struct pci_device_id ast_bmc_pci_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_ASPEED, PCI_DEVICE_ID_AST2500_VGA) },
	{ },
};
MODULE_DEVICE_TABLE(pci, ast_bmc_pci_table);

static struct pci_driver ast_bmc_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = ast_bmc_pci_table,
	.probe = ast_bmc_pci_probe,
	.remove = ast_bmc_pci_remove,
};

static int __init ast_init(void)
{
	return pci_register_driver(&ast_bmc_pci_driver);
}
static void __exit ast_exit(void)
{
	pci_unregister_driver(&ast_bmc_pci_driver);
}

module_init(ast_init);
module_exit(ast_exit);

MODULE_AUTHOR("Eddie James");
MODULE_DESCRIPTION("AST BMC DMA");
MODULE_LICENSE("GPL v2");
