version_settings(constraint='>=0.22.2')

load('ext://configmap', 'configmap_create')

# Generate the controller image.
docker_build(
    'diy-sm-controller',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/controller/',
        './internal/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'controller',
    },
)

# Generate the proxy image.
docker_build(
    'diy-sm-proxy',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/proxy/',
        './internal/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'proxy',
    },
    match_in_env_vars=True,
)

# Generate the proxy-init image.
docker_build(
    'diy-sm-proxy-init',
    context='.',
    dockerfile='./Dockerfile.proxy-init',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/proxy-init/',
        './internal/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'proxy-init',
    },
    match_in_env_vars=True,
)

# Generate the app-b image.
docker_build(
    'diy-sm-injector',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/injector/',
        './internal/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'injector',
    },
)

# Generate the app-a image.
docker_build(
    'diy-sm-app-a',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/app-a/',
        './internal/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'app-a',
    },
)

# Generate the app-b image.
docker_build(
    'diy-sm-app-b',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/app-b/',
        './internal/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'app-b',
    },
)

# Generate the proto files
local_resource(
    'protobuild',
    cmd='PATH="$PATH:$(pwd)/bin" buf generate',
    deps=[
        'proto',
        'buf.gen.yaml'
    ],
)

# Apply resources to the cluster
k8s_yaml('k8s/controller.yaml')
k8s_yaml('k8s/injector.yaml', allow_duplicates=True)
k8s_yaml('k8s/app-a.yaml')
k8s_yaml('k8s/app-b.yaml')
