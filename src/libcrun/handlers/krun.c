/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020, 2021 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE

#include <config.h>
#include "../custom-handler.h"
#include "../container.h"
#include "../utils.h"
#include "../linux.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <fcntl.h>
#include <sched.h>
#include <ocispec/runtime_spec_schema_config_schema.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_LIBKRUN
#  include <libkrun.h>
#endif

/* This allows us to build even with headers from older libkrun versions.
 * If the installed version of libkrun doesn't support this feature,
 * krun_add_net_unixstream() will return EINVAL.
 */
#ifndef NET_FLAG_DHCP_CLIENT
#  define NET_FLAG_DHCP_CLIENT (1 << 1)
#endif

/* libkrun has a hard-limit of 16 vCPUs per microVM. */
#define LIBKRUN_MAX_VCPUS 16

/* If the user doesn't configure the RAM amount, fallback to this value. */
#define LIBKRUN_DEFAULT_RAM_MIB 1024

/* The minimum amount of RAM for a viable microVM is 128 MB. */
#define LIBKRUN_MINIMUM_RAM_MIB 128

/* crun dumps the container configuration into this file, which will be read by
 * libkrun to set up the environment for the workload inside the microVM.
 */
#define KRUN_CONFIG_FILE ".krun_config.json"

/* The presence of this file indicates this is a container intended to be run
 * as a confidential workload inside a SEV-powered TEE.
 */
#define KRUN_SEV_FILE "/krun-sev.json"

/* This file contains configuration parameters for the microVM. crun needs to
 * read and parse it, using the information obtained from it to configure
 * libkrun as required.
 */
#define KRUN_VM_FILE "/.krun_vm.json"

#define KRUN_FLAVOR_AWS_NITRO "aws-nitro"
#define KRUN_FLAVOR_SEV "sev"

/* "krun" in ASCII. */
#define KRUN_SSH_VSOCK_PORT 0x6b72756e
/* This is in a mount namespace, not in the host filesystem. */
#define KRUN_SSH_SOCK_FILE "/.krun_ssh.sock"

#define PASST_FD_PARENT 0
#define PASST_FD_CHILD 1

struct krun_config
{
  void *handle;
  void *handle_sev;
  void *handle_awsnitro;
  bool sev;
  bool awsnitro;
  int32_t ctx_id;
  int32_t ctx_id_sev;
  int32_t ctx_id_awsnitro;
  bool has_kvm;
  bool has_awsnitro;
  int passt_fds[2];
  json_object *config_doc;
  json_object *config_tree;
  bool use_passt;
};

/* libkrun handler.  */
#if HAVE_DLOPEN && HAVE_LIBKRUN
static int32_t
libkrun_create_context (void *handle, libcrun_error_t *err)
{
  int32_t (*krun_create_ctx) ();
  int32_t ctx_id;

  krun_create_ctx = dlsym (handle, "krun_create_ctx");
  if (krun_create_ctx == NULL)
    return crun_make_error (err, 0, "could not find symbol in the krun library");

  ctx_id = krun_create_ctx ();
  if (UNLIKELY (ctx_id < 0))
    return crun_make_error (err, -ctx_id, "could not create krun context");

  return ctx_id;
}

static int
libkrun_configure_kernel (uint32_t ctx_id, void *handle, json_object *config_tree, libcrun_error_t *err)
{
  int32_t (*krun_set_kernel) (uint32_t ctx_id, const char *kernel_path,
                              uint32_t kernel_format, const char *initrd_path, const char *kernel_cmdline);
  json_object *kernel_path = NULL;
  json_object *kernel_format = NULL;
  json_object *val_initrd_path = NULL;
  json_object *val_kernel_cmdline = NULL;
  const char *initrd_path = NULL;
  const char *kernel_cmdline = NULL;
  int ret;

  /* kernel_path and kernel_format must be present */
  kernel_path = json_object_object_get (config_tree, "kernel_path");
  if (kernel_path == NULL || ! json_object_is_type (kernel_path, json_type_string))
    return 0;

  kernel_format = json_object_object_get (config_tree, "kernel_format");
  if (kernel_format == NULL || ! json_object_is_type (kernel_format, json_type_int))
    return 0;

  /* initrd and kernel_cmdline are optional */
  val_initrd_path = json_object_object_get (config_tree, "initrd_path");
  if (val_initrd_path != NULL && json_object_is_type (val_initrd_path, json_type_string))
    initrd_path = json_object_get_string (val_initrd_path);

  val_kernel_cmdline = json_object_object_get (config_tree, "kernel_cmdline");
  if (val_kernel_cmdline != NULL && json_object_is_type (val_kernel_cmdline, json_type_string))
    kernel_cmdline = json_object_get_string (val_kernel_cmdline);

  krun_set_kernel = dlsym (handle, "krun_set_kernel");
  if (krun_set_kernel == NULL)
    return crun_make_error (err, 0, "could not find symbol in krun library");

  ret = krun_set_kernel (ctx_id,
                         json_object_get_string (kernel_path),
                         (uint32_t) json_object_get_int64 (kernel_format),
                         initrd_path, kernel_cmdline);

  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "could not configure a krun external kernel");

  return 0;
}

static int
libkrun_enable_virtio_gpu (struct krun_config *kconf, uint32_t virgl_flags)
{
  int32_t (*krun_set_gpu_options) (uint32_t ctx_id, uint32_t virgl_flags);
  krun_set_gpu_options = dlsym (kconf->handle, "krun_set_gpu_options");

  // ignore if dlsym fails
  if (krun_set_gpu_options == NULL)
    return 0;

  return krun_set_gpu_options (kconf->ctx_id, virgl_flags);
}

static int
libkrun_read_vm_config (struct krun_config *kconf, int rootfsfd, const char *rootfs, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *config = NULL;
  cleanup_close int fd = -1;

  fd = safe_openat (rootfsfd, rootfs, KRUN_VM_FILE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0, err);
  if (fd < 0)
    {
      // The configuration file is optional, don't generate an error if it's missing.
      if (crun_error_get_errno (err) == ENOENT)
        {
          crun_error_release (err);
          return 0;
        }
      return fd;
    }

  ret = read_all_fd (fd, "krun configuration file", &config, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = parse_json_file (&kconf->config_doc, config, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  kconf->config_tree = kconf->config_doc;
  return 0;
}

/*
 * Default to parsing the OCI annotations to find the specified microVM
 * attribute. If the desired attribute is not found within the OCI annotations
 * or the krun_vm.json file, then return a negative integer.
 *
 * The configuration precedence is as follows:
 * OCI annotations -> krun_vm.json.
 */
static int
libkrun_parse_resource_configuration (json_object *config_tree, libcrun_container_t *container, const char *annotation, const char *key)
{
  char *val_str, *endptr;
  int val = -1;
  json_object *val_json = NULL;

  val_str = (char *) find_annotation (container, annotation);
  if (val_str != NULL)
    {
      errno = 0;
      val = (int) strtol (val_str, &endptr, 10);
      if (errno != 0 || endptr == val_str || *endptr != '\0')
        /* Annotations value is not a valid integer. */
        error (EXIT_FAILURE, 0, "krun annotation %s value cannot be converted to an integer", annotation);

      if (val < 0)
        error (EXIT_FAILURE, 0, "krun annotation %s value must be a positive integer", annotation);

      return val;
    }
  else if (config_tree != NULL)
    {
      val_json = json_object_object_get (config_tree, key);
      if (val_json == NULL)
        return val;
      if (! json_object_is_type (val_json, json_type_int))
        error (EXIT_FAILURE, 0, "krun krun_vm.json %s value is not an integer", key);

      val = (int) json_object_get_int64 (val_json);
    }

  return val;
}

static int
libkrun_configure_vm (uint32_t ctx_id, void *handle, struct krun_config *kconf, libcrun_container_t *container, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int32_t (*krun_set_vm_config) (uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);
  int32_t (*krun_add_net_unixstream) (uint32_t ctx_id, const char *c_path, int fd, uint8_t *const c_mac, uint32_t features, uint32_t flags);
  int cpus, ram_mib, gpu_flags, nested_virt, ret;
  cpu_set_t set;

  cpus = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.cpus", "cpus");
  if (cpus <= 0)
    {
      CPU_ZERO (&set);
      if (sched_getaffinity (getpid (), sizeof (set), &set) == 0)
        cpus = MIN (CPU_COUNT (&set), LIBKRUN_MAX_VCPUS);
      else
        cpus = 1;
    }

  ram_mib = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.ram_mib", "ram_mib");
  if (ram_mib <= LIBKRUN_MINIMUM_RAM_MIB)
    {
      if (def && def->linux && def->linux->resources && def->linux->resources->memory
          && def->linux->resources->memory->limit_present)
        ram_mib = def->linux->resources->memory->limit / (1024 * 1024);
      else
        ram_mib = LIBKRUN_DEFAULT_RAM_MIB;
    }

  krun_set_vm_config = dlsym (handle, "krun_set_vm_config");

  if (krun_set_vm_config == NULL)
    return crun_make_error (err, 0, "could not find symbol in the krun library");

  ret = krun_set_vm_config (ctx_id, cpus, ram_mib);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "could not set krun vm configuration");

  gpu_flags = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.gpu_flags", "gpu_flags");
  if (gpu_flags > 0)
    {
      if (access ("/dev/dri", F_OK) != 0)
        return crun_make_error (err, errno, "gpu requested but /dev/dri is not available");

      if ((gpu_flags & VIRGLRENDERER_RENDER_SERVER) != 0
          && access ("/usr/libexec/virgl_render_server", F_OK) != 0)
        return crun_make_error (err, errno, "gpu requested but virgl_render_server is not available");

      ret = libkrun_enable_virtio_gpu (kconf, gpu_flags);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "could not enable virtio gpu");
    }

  nested_virt = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.nested_virt", "nested_virt");
  if (nested_virt > 0)
    {
      int32_t (*krun_check_nested_virt) (void);
      int32_t (*krun_set_nested_virt) (uint32_t ctx_id, bool enabled);

      krun_check_nested_virt = dlsym (handle, "krun_check_nested_virt");
      if (krun_check_nested_virt != NULL && krun_check_nested_virt () != 1)
        libcrun_warning ("nested virtualization requested but may not be supported on this host");

      krun_set_nested_virt = dlsym (handle, "krun_set_nested_virt");
      if (krun_set_nested_virt == NULL)
        return crun_make_error (err, 0, "could not find symbol `krun_set_nested_virt` in the krun library");

      ret = krun_set_nested_virt (ctx_id, true);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "could not enable nested virtualization");
    }

  int32_t (*krun_add_vsock) (uint32_t ctx_id, uint32_t tsi_features);
  krun_add_vsock = dlsym (handle, "krun_add_vsock");
  uint32_t tsi_features = kconf->use_passt ? 0 : KRUN_TSI_HIJACK_INET;
  if (krun_add_vsock != NULL)
    krun_add_vsock (ctx_id, tsi_features);

  unlink (KRUN_SSH_SOCK_FILE);

  int32_t (*krun_add_vsock_port2) (uint32_t ctx_id, uint32_t port, const char *c_filepath, bool listen);
  krun_add_vsock_port2 = dlsym (handle, "krun_add_vsock_port2");
  if (krun_add_vsock_port2 == NULL)
    return crun_make_error (err, 0, "exec server requested but could not find symbol `krun_add_vsock_port2` in the krun library");

  ret = krun_add_vsock_port2 (ctx_id, KRUN_SSH_VSOCK_PORT, KRUN_SSH_SOCK_FILE, true);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "could not configure the krun exec vsock port");

  if (kconf->use_passt)
    {
      krun_add_net_unixstream = dlsym (handle, "krun_add_net_unixstream");
      if (krun_add_net_unixstream == NULL)
        return crun_make_error (err, 0, "could not find symbol `krun_add_net_unixstream` in the krun library");

      uint8_t mac[] = { 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee };
      ret = krun_add_net_unixstream (ctx_id, NULL, kconf->passt_fds[PASST_FD_PARENT], &mac[0], COMPAT_NET_FEATURES, NET_FLAG_DHCP_CLIENT);
      if (UNLIKELY (ret == -EINVAL))
        ret = krun_add_net_unixstream (ctx_id, NULL, kconf->passt_fds[PASST_FD_PARENT], &mac[0], COMPAT_NET_FEATURES, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "could not set krun net configuration");
    }

  if (kconf->config_tree != NULL)
    {
      /* Try to configure an external kernel. If the configuration file doesn't
       * specify a kernel, libkrun automatically fall back to using libkrunfw,
       * if the library is present and was loaded while creating the context.
       */
      ret = libkrun_configure_kernel (ctx_id, handle, kconf->config_tree, err);
      if (UNLIKELY (ret))
        return ret;
    }

  return 0;
}

static int
libkrun_configure_flavor (void *cookie, json_object *config_tree, libcrun_container_t *container, libcrun_error_t *err)
{
  int ret, sev_indicated = 0, awsnitro_indicated = 0;
  struct krun_config *kconf = (struct krun_config *) cookie;
  json_object *val_flavor = NULL;
  const char *flavor = NULL;
  void *close_handles[2];

  close_handles[0] = NULL;
  close_handles[1] = NULL;

  // Check if the user provided the krun variant through OCI annotations.
  flavor = find_annotation (container, "krun.variant");
  if (flavor == NULL && config_tree != NULL)
    {
      // If the user doesn't specify a variant via OCI annotations, check the krun VM config to see if the "flavor" field was populated.
      val_flavor = json_object_object_get (config_tree, "flavor");
      if (val_flavor != NULL && json_object_is_type (val_flavor, json_type_string))
        flavor = json_object_get_string (val_flavor);
    }

  if (flavor != NULL)
    {
      sev_indicated |= strcmp (flavor, KRUN_FLAVOR_SEV) == 0;
      awsnitro_indicated |= strcmp (flavor, KRUN_FLAVOR_AWS_NITRO) == 0;
    }

  // To maintain backward compatibility, also use the SEV flavor if the
  // KRUN_SEV_FILE was found.
  sev_indicated |= access (KRUN_SEV_FILE, F_OK) == 0;

  if (sev_indicated)
    {
      if (kconf->handle_sev == NULL)
        error (EXIT_FAILURE, 0, "the container requires libkrun-sev but it's not available");

      close_handles[0] = kconf->handle;
      close_handles[1] = kconf->handle_awsnitro;

      kconf->handle = kconf->handle_sev;
      kconf->ctx_id = kconf->ctx_id_sev;
      kconf->sev = true;
    }
  else if (awsnitro_indicated)
    {
      if (kconf->handle_awsnitro == NULL)
        error (EXIT_FAILURE, 0, "the container requires libkrun-awsnitro but it's not available");

      close_handles[0] = kconf->handle;
      close_handles[1] = kconf->handle_sev;

      kconf->handle = kconf->handle_awsnitro;
      kconf->ctx_id = kconf->ctx_id_awsnitro;
      kconf->awsnitro = true;
    }
  else
    {
      if (kconf->handle == NULL)
        error (EXIT_FAILURE, 0, "the container requires libkrun but it's not available");

      close_handles[0] = kconf->handle_sev;
      close_handles[1] = kconf->handle_awsnitro;
    }

  // We no longer need the other two libkrun handles.
  for (int i = 0; i < 2; i++)
    {
      if (close_handles[i] == NULL)
        continue;

      ret = dlclose (close_handles[i]);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, 0, "could not unload handle: `%s`", dlerror ());
    }

  return 0;
}

static int
libkrun_exec (void *cookie, libcrun_container_t *container, const char *pathname, char *const argv[])
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int32_t (*krun_init_log) (int target_fd, uint32_t level, uint32_t style, uint32_t options);
  int (*krun_start_enter) (uint32_t ctx_id);
  int32_t (*krun_add_virtiofs2) (uint32_t ctx_id, const char *c_tag, const char *c_path, uint64_t shm_size);
  int32_t (*krun_set_root_disk) (uint32_t ctx_id, const char *disk_path);
  int32_t (*krun_set_tee_config_file) (uint32_t ctx_id, const char *file_path);
  int32_t (*krun_set_console_output) (uint32_t ctx_id, const char *c_filepath);
  int32_t (*krun_set_exec) (uint32_t ctx_id, const char *exec_path,
                            const char *const argv[], const char *const envp[]);
  struct krun_config *kconf = (struct krun_config *) cookie;
  void *handle;
  int32_t ctx_id, ret;
  libcrun_error_t err;

  ret = libkrun_configure_flavor (cookie, kconf->config_tree, container, &err);
  if (UNLIKELY (ret < 0))
    {
      int errcode = crun_error_get_errno (&err);
      crun_error_release (&err);
      error (EXIT_FAILURE, errcode, "unable to configure libkrun flavor");
    }

  // /dev/kvm is required for all non AWS nitro workloads.
  if (! kconf->awsnitro && ! kconf->has_kvm)
    error (EXIT_FAILURE, 0, "`/dev/kvm` unavailable");

  handle = kconf->handle;
  ctx_id = kconf->ctx_id;

  krun_init_log = dlsym (handle, "krun_init_log");
  krun_start_enter = dlsym (handle, "krun_start_enter");
  if (krun_init_log == NULL || krun_start_enter == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in the krun library");

  /* Set log level according to crun's verbosity. */
  switch (libcrun_get_verbosity ())
    {
    case LIBCRUN_VERBOSITY_DEBUG:
      krun_init_log (KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_DEBUG, KRUN_LOG_STYLE_AUTO, 0);
      break;
    case LIBCRUN_VERBOSITY_WARNING:
      krun_init_log (KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_WARN, KRUN_LOG_STYLE_AUTO, 0);
      break;
    default:
      krun_init_log (KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_ERROR, KRUN_LOG_STYLE_AUTO, 0);
      break;
    }

  if (kconf->sev)
    {
      krun_set_root_disk = dlsym (handle, "krun_set_root_disk");
      krun_set_tee_config_file = dlsym (handle, "krun_set_tee_config_file");
      if (krun_set_root_disk == NULL || krun_set_tee_config_file == NULL)
        error (EXIT_FAILURE, 0, "could not find symbol in `libkrun-sev.so`");

      ret = krun_set_root_disk (ctx_id, "/disk.img");
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set root disk");

      ret = krun_set_tee_config_file (ctx_id, KRUN_SEV_FILE);
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set krun tee config file");
    }
  else
    {
      json_object *val_virtiofs_tag = NULL;
      json_object *val_virtiofs_shm_size = NULL;
      const char *virtiofs_tag = NULL;
      // Default to a conservative DAX size of 512MB, just like krun_set_root() does.
      uint64_t virtiofs_shm_size = 512 * 1024 * 1024ULL;

      if (kconf->config_tree != NULL)
        {
          val_virtiofs_tag = json_object_object_get (kconf->config_tree, "virtiofs_tag");
          if (val_virtiofs_tag != NULL && json_object_is_type (val_virtiofs_tag, json_type_string))
            virtiofs_tag = json_object_get_string (val_virtiofs_tag);

          val_virtiofs_shm_size = json_object_object_get (kconf->config_tree, "virtiofs_shm_size");
          if (val_virtiofs_shm_size != NULL && json_object_is_type (val_virtiofs_shm_size, json_type_int))
            virtiofs_shm_size = json_object_get_uint64 (val_virtiofs_shm_size);
        }

      if (virtiofs_tag == NULL)
        virtiofs_tag = "/dev/root";

      krun_add_virtiofs2 = dlsym (handle, "krun_add_virtiofs2");

      if (krun_add_virtiofs2 == NULL)
        error (EXIT_FAILURE, 0, "could not find symbol `krun_add_virtiofs2` in `libkrun.so`");

      ret = krun_add_virtiofs2 (ctx_id, virtiofs_tag, "/", virtiofs_shm_size);
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not add virtiofs root with tag `%s`", virtiofs_tag);
    }

  if (kconf->awsnitro)
    {
      krun_set_console_output = dlsym (handle, "krun_set_console_output");
      krun_set_exec = dlsym (handle, "krun_set_exec");
      if (krun_set_console_output == NULL || krun_set_exec == NULL)
        error (EXIT_FAILURE, 0, "could not find symbol in `libkrun-awsnitro.so`");

      // Redirect all enclave output (read from vsock) to stdout.
      ret = krun_set_console_output (ctx_id, "/dev/stdout");
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not redirect enclave output to stdout");

      ret = krun_set_exec (ctx_id, pathname, (const char *const *) argv,
                           (const char *const *) def->process->env);
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set enclave execution arguments");
    }
  else
    {
      // Add console for libkrun 2.0.
      int32_t (*krun_add_virtio_console_default) (uint32_t ctx_id, int input_fd, int output_fd, int err_fd);

      krun_add_virtio_console_default = dlsym (handle, "krun_add_virtio_console_default");
      if (krun_add_virtio_console_default != NULL)
        {
          ret = krun_add_virtio_console_default (ctx_id, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO);
          if (UNLIKELY (ret < 0))
            error (EXIT_FAILURE, -ret, "could not add the default virtio-console");
        }
    }

  ret = libkrun_configure_vm (ctx_id, handle, kconf, container, &err);
  if (UNLIKELY (ret))
    {
      int errcode = crun_error_get_errno (&err);
      libcrun_error_t *tmp_err = &err;
      libcrun_error_write_warning_and_release (NULL, &tmp_err);
      error (EXIT_FAILURE, errcode, "could not configure krun vm");
    }

  json_object_put (kconf->config_doc);

  ret = krun_start_enter (ctx_id);
  if (UNLIKELY (ret < 0))
    error (EXIT_FAILURE, -ret, "could not start krun");

  return ret;
}

static int
libkrun_exec_ssh (void *cookie, libcrun_container_t *container,
                  const char *pathname arg_unused,
                  runtime_spec_schema_config_schema_process *process)
{
  struct krun_config *kconf = (struct krun_config *) cookie;
  cleanup_free char *sock_path = NULL;
  cleanup_free char *sock_addr = NULL;
  size_t i, j;
  size_t n = process->args_len;
  size_t e = process->env_len;
  char **argv = xmalloc0 ((6 + e + n) * sizeof (char *));

  // Access the Unix socket through ~/.local/share/containers/storage/overlay/SOME_HEX_STRING/merged.
  xasprintf (&sock_path, "%s" KRUN_SSH_SOCK_FILE, container->container_def->root->path);

  // This is an ugly hack, but we need to wait until the socket exists.
  // Otherwise sometimes the Forgejo CI tries to exec before the SSH socket is ready.
  if (access (sock_path, F_OK) != 0)
    {
      i = 0;
      while (access (sock_path, F_OK) != 0)
        {
          if (i == 10)
            error (EXIT_FAILURE, errno, "krun exec: ssh socket not found");
          // Retry every second.
          sleep (1);
          i++;
        }
      // Additionally wait a bit longer so that the SSH server is fully up.
      sleep (1);
    }

  xasprintf (&sock_addr, "unix%s", sock_path);

  i = 0;
  argv[i++] = "ssh";
  // Hide "Permanently added ADDRESS to the list of known hosts."
  argv[i++] = "-q";
  // Fix permission error.
  argv[i++] = "-F/usr/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf";
  if (process->terminal)
    argv[i++] = "-tt";
  if (e > 0)
    {
      // I hate C string processing.
      char *prefix = "-o=SetEnv=";
      size_t prefix_len = strlen (prefix);
      size_t total_len = prefix_len + e;
      char *p, *setenv_val, *dest;

      for (j = 0; j < e; j++)
        {
          for (p = process->env[j]; *p != '\0'; p++)
            {
              if (*p == '\\' || *p == ' ' || *p == '\'' || *p == '"')
                total_len += 2;
              else
                total_len += 1;
            }
        }

      setenv_val = xmalloc (total_len);
      strcpy (setenv_val, prefix);
      dest = setenv_val + prefix_len;
      for (j = 0; j < e; j++)
        {
          for (p = process->env[j]; *p != '\0'; p++)
            {
              if (*p == '\\' || *p == ' ' || *p == '\'' || *p == '"')
                *dest++ = '\\';
              *dest++ = *p;
            }
          if (j < e - 1)
            *dest++ = ' ';
        }
      *dest = '\0';
      argv[i++] = setenv_val;
    }
  argv[i++] = sock_addr;
  for (j = 0; j < n; j++)
    argv[i++] = process->args[j];
  argv[i] = NULL;

  execvp ("ssh", argv);
  error (EXIT_FAILURE, errno, "krun exec: execvp ssh");
  return -1;
}

static int
libkrun_kill_ssh (void *cookie, libcrun_container_t *container, pid_t pid, int signal, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema_process process = {
    0,
  };
  char sig_str[16];
  char *args[2];
  pid_t ssh_pid;
  int ret, devnull;

  // Handle SIGKILL ourselves instead of using libkrun_exec_ssh
  if (signal == SIGKILL)
    {
      ret = kill (pid, SIGKILL);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "kill container");
      return 0;
    }

  snprintf (sig_str, sizeof (sig_str), "%d", signal);
  args[0] = "\x01KRUN_STOP";
  args[1] = sig_str;
  process.args = args;
  process.args_len = 2;

  ssh_pid = fork ();
  if (UNLIKELY (ssh_pid < 0))
    return crun_make_error (err, errno, "fork");

  if (ssh_pid == 0)
    {
      devnull = open ("/dev/null", O_RDWR);
      if (devnull >= 0)
        {
          dup2 (devnull, STDIN_FILENO);
          dup2 (devnull, STDOUT_FILENO);
          dup2 (devnull, STDERR_FILENO);
        }
      libkrun_exec_ssh (cookie, container, NULL, &process);
      _safe_exit (EXIT_FAILURE);
    }

  return 0;
}

static int
libkrun_start_passt (void *cookie, libcrun_container_t *container)
{
  struct krun_config *kconf = (struct krun_config *) cookie;
  pid_t pid;
  char *passt_argv[10];
  char fd_as_str[16];
  int use_passt;
  int argv_idx;
  int status;
  int null;
  int ret;

  use_passt = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.use_passt", "use_passt");
  if (use_passt > 0)
    kconf->use_passt = 1;
  else
    return 0;

  ret = socketpair (AF_UNIX, SOCK_STREAM, 0, kconf->passt_fds);
  if (UNLIKELY (ret < 0))
    return ret;
  snprintf (fd_as_str, sizeof (fd_as_str), "%d", kconf->passt_fds[PASST_FD_CHILD]);

  argv_idx = 0;
  passt_argv[argv_idx++] = (char *) "passt";
  passt_argv[argv_idx++] = (char *) "-t";
  passt_argv[argv_idx++] = (char *) "all";

  if (! kconf->has_awsnitro)
    {
      passt_argv[argv_idx++] = (char *) "-u";
      passt_argv[argv_idx++] = (char *) "all";
      passt_argv[argv_idx++] = (char *) "--no-dhcp-dns";
    }

  /* Set --no-map-gw. If the gateway for the network is also the DNS server
   * we won't be able to query the DNS server without --no-map-gw.
   * See discussion in https://github.com/containers/crun/pull/2099
   */
  passt_argv[argv_idx++] = (char *) "--no-map-gw";

  passt_argv[argv_idx++] = (char *) "--fd";
  passt_argv[argv_idx++] = fd_as_str;
  passt_argv[argv_idx] = NULL;

  pid = fork ();
  if (pid < 0)
    return pid;
  else if (pid == 0)
    {
      close (kconf->passt_fds[PASST_FD_PARENT]);

      null = open ("/dev/null", O_WRONLY);
      if (null == -1)
        _exit (EXIT_FAILURE);

      // Redirect passt's stdout and stderr to /dev/null, as closing them here
      // instead will cause passt to exit with an error.
      dup2 (null, STDOUT_FILENO);
      dup2 (null, STDERR_FILENO);
      close (null);

      execvp ("passt", passt_argv);
      // Only reachable on error.
      _exit (EXIT_FAILURE);
    }

  close (kconf->passt_fds[PASST_FD_CHILD]);

  // Wait for passt to daemonize itself.
  waitpid (pid, &status, 0);
  if (! (WIFEXITED (status)) || WEXITSTATUS (status) != 0)
    return -1;

  return 0;
}

/* libkrun_create_kvm_device: explicitly adds kvm device.  */
static int
libkrun_configure_container (void *cookie, enum handler_configure_phase phase,
                             libcrun_context_t *context, libcrun_container_t *container,
                             const char *rootfs, libcrun_error_t *err)
{
  int ret, rootfsfd;
  size_t i;
  struct krun_config *kconf = (struct krun_config *) cookie;
  struct device_s kvm_device = { "/dev/kvm", "c", 10, 232, 0666, 0, 0 };
  struct device_s sev_device = { "/dev/sev", "c", 10, 124, 0666, 0, 0 };
  struct device_s nitro_device = { "/dev/nitro_enclaves", "c", 10, 122, 0666, 0, 0 };
  cleanup_close int devfd = -1;
  cleanup_close int rootfsfd_cleanup = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  bool create_sev = false, create_awsnitro = false;
  bool is_user_ns;

  if (rootfs == NULL)
    rootfsfd = AT_FDCWD;
  else
    {
      rootfsfd = rootfsfd_cleanup = open (rootfs, O_PATH | O_CLOEXEC);
      if (UNLIKELY (rootfsfd < 0))
        return crun_make_error (err, errno, "open `%s`", rootfs);
    }

  if (phase == HANDLER_CONFIGURE_BEFORE_USERNS)
    {
      cleanup_free char *origin_config_path = NULL;
      cleanup_free char *state_dir = NULL;
      cleanup_free char *config = NULL;
      cleanup_close int fd = -1;
      size_t config_size;

      ret = libcrun_get_state_directory (&state_dir, context->state_root, context->id, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&origin_config_path, err, state_dir, "config.json", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = read_all_file (origin_config_path, &config, &config_size, err);
      if (UNLIKELY (ret < 0))
        return ret;

      /* CVE-2025-24965: the content below rootfs cannot be trusted because it is controlled by the user.  We
         must ensure the file is opened below the rootfs directory.  */
      fd = safe_openat (rootfsfd, rootfs, KRUN_CONFIG_FILE, WRITE_FILE_DEFAULT_FLAGS | O_NOFOLLOW, S_IRUSR | S_IRGRP | S_IROTH, err);
      if (UNLIKELY (fd < 0))
        return fd;

      ret = safe_write (fd, KRUN_CONFIG_FILE, config, config_size, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libkrun_read_vm_config (kconf, rootfsfd, rootfs, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (phase != HANDLER_CONFIGURE_AFTER_MOUNTS)
    return 0;

  ret = libkrun_start_passt (cookie, container);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "start passt");

  /* Do nothing if /dev/kvm is already present in spec */
  for (i = 0; i < def->linux->devices_len; i++)
    {
      if (strcmp (def->linux->devices[i]->path, "/dev/kvm") == 0)
        return 0;
    }

  if (kconf->handle_sev != NULL)
    {
      create_sev = true;
      for (i = 0; i < def->linux->devices_len; i++)
        {
          if (strcmp (def->linux->devices[i]->path, "/dev/sev") == 0)
            {
              create_sev = false;
              break;
            }
        }
    }

  if (kconf->handle_awsnitro != NULL)
    {
      create_awsnitro = true;
      for (i = 0; i < def->linux->devices_len; i++)
        {
          if (strcmp (def->linux->devices[i]->path, "/dev/nitro_enclaves") == 0)
            {
              create_awsnitro = false;
              break;
            }
        }
    }

  devfd = safe_openat (rootfsfd, rootfs, "dev", O_PATH | O_DIRECTORY | O_CLOEXEC, 0, err);
  if (UNLIKELY (devfd < 0))
    return devfd;

  ret = check_running_in_user_namespace (err);
  if (UNLIKELY (ret < 0))
    return ret;
  is_user_ns = ret;

  if (kconf->has_kvm)
    {
      ret = libcrun_create_dev (container, devfd, -1, &kvm_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (create_sev)
    {
      ret = libcrun_create_dev (container, devfd, -1, &sev_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        {
          ret = dlclose (kconf->handle_sev);
          if (UNLIKELY (ret < 0))
            return ret;
          kconf->handle_sev = NULL;
        }
    }

  if (create_awsnitro)
    {
      ret = libcrun_create_dev (container, devfd, -1, &nitro_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        {
          ret = dlclose (kconf->handle_awsnitro);
          if (UNLIKELY (ret < 0))
            return ret;
          kconf->handle_awsnitro = NULL;
        }
    }

  return 0;
}

static int
libkrun_load (void **cookie, libcrun_error_t *err)
{
  int32_t ret;
  struct krun_config *kconf;
  const char *libkrun_so = "libkrun.so.2";
  const char *libkrun_sev_so = "libkrun-sev.so.2";
  const char *libkrun_awsnitro_so = "libkrun-awsnitro.so.2";

  kconf = malloc (sizeof (struct krun_config));
  if (kconf == NULL)
    return crun_make_error (err, 0, "could not allocate memory for krun_config");
  memset (kconf, 0, sizeof (struct krun_config));

  kconf->handle = dlopen (libkrun_so, RTLD_NOW);
  kconf->handle_sev = dlopen (libkrun_sev_so, RTLD_NOW);
  kconf->handle_awsnitro = dlopen (libkrun_awsnitro_so, RTLD_NOW);

  if (kconf->handle == NULL && kconf->handle_sev == NULL && kconf->handle_awsnitro == NULL)
    {
      free (kconf);
      return crun_make_error (err, 0, "failed to open `%s`, `%s`, and `%s` for krun_config: %s", libkrun_so, libkrun_sev_so, libkrun_awsnitro_so, dlerror ());
    }

  kconf->sev = false;
  kconf->awsnitro = false;

  /* Newer versions of libkrun no longer link against libkrunfw and
     instead they open it when creating the context. This implies
     we need to call "krun_create_ctx" before switching namespaces
     or it won't be able to find the library bundling the kernel. */
  if (kconf->handle)
    {
      ret = libkrun_create_context (kconf->handle, err);
      if (UNLIKELY (ret < 0))
        goto error;
      kconf->ctx_id = ret;
    }

  if (kconf->handle_sev)
    {
      ret = libkrun_create_context (kconf->handle_sev, err);
      if (UNLIKELY (ret < 0))
        goto error;
      kconf->ctx_id_sev = ret;
    }
  if (kconf->handle_awsnitro)
    {
      ret = libkrun_create_context (kconf->handle_awsnitro, err);
      if (UNLIKELY (ret < 0))
        goto error;
      kconf->ctx_id_awsnitro = ret;
    }

  *cookie = kconf;

  return 0;

error:
  if (kconf->handle)
    dlclose (kconf->handle);
  if (kconf->handle_sev)
    dlclose (kconf->handle_sev);
  if (kconf->handle_awsnitro)
    dlclose (kconf->handle_awsnitro);
  free (kconf);
  return ret;
}

static int
libkrun_unload (void *cookie, libcrun_error_t *err)
{
  int r;

  struct krun_config *kconf = (struct krun_config *) cookie;
  if (kconf != NULL)
    {
      if (kconf->handle != NULL)
        {
          r = dlclose (kconf->handle);
          if (UNLIKELY (r != 0))
            return crun_make_error (err, 0, "could not unload handle: `%s`", dlerror ());
        }
      if (kconf->handle_sev != NULL)
        {
          r = dlclose (kconf->handle_sev);
          if (UNLIKELY (r != 0))
            return crun_make_error (err, 0, "could not unload handle_sev: `%s`", dlerror ());
        }
      if (kconf->handle_awsnitro != NULL)
        {
          r = dlclose (kconf->handle_awsnitro);
          if (UNLIKELY (r != 0))
            return crun_make_error (err, 0, "could not unload handle_awsnitro: `%s`", dlerror ());
        }
      free (kconf);
    }
  return 0;
}

static runtime_spec_schema_defs_linux_device_cgroup *
make_oci_spec_dev (const char *type, dev_t device, bool allow, const char *access)
{
  runtime_spec_schema_defs_linux_device_cgroup *dev = xmalloc0 (sizeof (*dev));

  dev->allow = allow;
  dev->allow_present = 1;

  dev->type = xstrdup (type);

  dev->major = major (device);
  dev->major_present = 1;

  dev->minor = minor (device);
  dev->minor_present = 1;

  dev->access = xstrdup (access);

  return dev;
}

static int
libkrun_modify_oci_configuration (void *cookie arg_unused, libcrun_context_t *context arg_unused,
                                  runtime_spec_schema_config_schema *def,
                                  libcrun_error_t *err)
{
  const size_t device_size = sizeof (runtime_spec_schema_defs_linux_device_cgroup);
  struct krun_config *kconf = (struct krun_config *) cookie;
  struct stat st_kvm, st_sev, st_awsnitro;
  bool has_kvm = true, has_sev = true, has_awsnitro = true;
  size_t old_len, new_len;
  int ret;

  /* Always allow the /dev/kvm device.  */

  ret = stat ("/dev/kvm", &st_kvm);
  if (UNLIKELY (ret < 0))
    {
      if (errno != ENOENT)
        return crun_make_error (err, errno, "stat `/dev/kvm`");
      has_kvm = false;
    }

  ret = stat ("/dev/sev", &st_sev);
  if (UNLIKELY (ret < 0))
    {
      if (errno != ENOENT)
        return crun_make_error (err, errno, "stat `/dev/sev`");
      has_sev = false;
    }

  ret = stat ("/dev/nitro_enclaves", &st_awsnitro);
  if (UNLIKELY (ret < 0))
    {
      if (errno != ENOENT)
        return crun_make_error (err, errno, "stat `/dev/nitro_enclaves`");
      has_awsnitro = false;
    }

  kconf->has_kvm = has_kvm;
  kconf->has_awsnitro = has_awsnitro;

  if (! has_kvm && ! has_awsnitro)
    return 0;

  /* spec says these are optional, ensure they exist so we can add our devices */
  if (def->linux == NULL)
    def->linux = xmalloc0 (sizeof (runtime_spec_schema_config_linux));

  if (def->linux->resources == NULL)
    def->linux->resources = xmalloc0 (sizeof (runtime_spec_schema_config_linux_resources));

  old_len = def->linux->resources->devices_len;
  new_len = old_len;
  if (has_kvm)
    new_len += has_sev ? 2 : 1;
  if (has_awsnitro)
    new_len += 1;

  def->linux->resources->devices = xrealloc (def->linux->resources->devices, device_size * (new_len + 1));
  def->linux->resources->devices_len = new_len;

  if (has_kvm)
    {
      def->linux->resources->devices[old_len++] = make_oci_spec_dev ("a", st_kvm.st_rdev, true, "rwm");
      if (has_sev)
        def->linux->resources->devices[old_len++] = make_oci_spec_dev ("a", st_sev.st_rdev, true, "rwm");
    }

  if (has_awsnitro)
    def->linux->resources->devices[old_len++] = make_oci_spec_dev ("a", st_awsnitro.st_rdev, true, "rwm");

  return 0;
}

static int
libkrun_close_fds (void *cookie, libcrun_container_t *container, int preserve_fds, libcrun_error_t *err)
{
  struct krun_config *kconf = (struct krun_config *) cookie;
  int first_fd_to_close = preserve_fds + 3;
  int passt_fd;
  int i;

  if (kconf->use_passt)
    {
      passt_fd = kconf->passt_fds[PASST_FD_PARENT];

      if (first_fd_to_close <= passt_fd)
        {
          for (i = first_fd_to_close; i < passt_fd; i++)
            {
              // If we're closing proc_fd, make sure to invalidate it.
              if (i == container->proc_fd)
                container->proc_fd = -1;
              close (i);
            }

          first_fd_to_close = passt_fd + 1;
        }
    }

  return mark_or_close_fds_ge_than (container, first_fd_to_close, true, err);
}

struct custom_handler_s handler_libkrun = {
  .name = "krun",
  .alias = NULL,
  .feature_string = "LIBKRUN",
  .load = libkrun_load,
  .unload = libkrun_unload,
  .run_func = libkrun_exec,
  .exec_func = libkrun_exec_ssh,
  .kill_func = libkrun_kill_ssh,
  .configure_container = libkrun_configure_container,
  .modify_oci_configuration = libkrun_modify_oci_configuration,
  .close_fds = libkrun_close_fds,
};

#endif
