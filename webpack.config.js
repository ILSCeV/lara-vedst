const path = require('path');
const webpack = require('webpack');
const LiveReloadPlugin = require('webpack-livereload-plugin');
const MiniCssExtractPlugin = require("mini-css-extract-plugin");
const PhpManifestPlugin = require('webpack-php-manifest');
const CleanWebpackPlugin = require('clean-webpack-plugin');
const devMode = process.env.NODE_ENV !== 'production';
//const devMode = false;

module.exports = {
  entry: {
    lara: './resources/assets/ts/lara.ts',
  },
  module: {
    rules: [
      {
        test: /isotope\-|fizzy\-ui\-utils|desandro\-|masonry|outlayer|get\-size|doc\-ready|eventie|eventemitter/,
        loader: 'imports-loader?define=>false&this=>window'
      },
      //bootstrap and bootbox need jQuery to be available, so make it available with the imports loader
      {
        test: /bootstrap.+\.(jsx|js)$/,
        loader: 'imports-loader?jQuery=jquery,$=jquery,this=>window'
      },
      {
        test: /bootbox.+\.(jsx|js)$/,
        loader: 'imports-loader?jQuery=jquery,$=jquery,this=>window'
      },
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/
      },
      {
        test: /\.(sa|sc|c)ss$/,
        use: [
          {
            loader: MiniCssExtractPlugin.loader,
            options: {
              sourceMap: devMode
            }
          },
          'css-loader',
          {
            loader: 'postcss-loader',
            options: {
              plugins: function () { // post css plugins, can be exported to postcss.config.js
                return [
                  require('precss'),
                  require('autoprefixer')
                ];
              },
              sourceMap: devMode
            },
          },
          {
            loader: 'sass-loader',
            options: {
              sourceMap: devMode,
              outputStyle: 'expanded'
            }
          },
        ],
      },
      {
        test: /\.(woff(2)?|ttf|eot|svg)(\?v=\d+\.\d+\.\d+)?$/,
        use: [{
          loader: 'file-loader',
          options: {
            name: '[name].[ext]',
            outputPath: 'fonts/'
          }
        }]
      },
    ]
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js', '.css', '.scss']
  },
  output: {
    filename: devMode ? '[name].js' : '[name].[hash].js',
    path: path.resolve(__dirname, 'public/'),
  },
  devtool: devMode ?'inline-source-map' : false,
  plugins: [
    new CleanWebpackPlugin(),
    new LiveReloadPlugin(),
    new MiniCssExtractPlugin({
      // Options similar to the same options in webpackOptions.output
      // both options are optional
      filename: devMode ? '[name].css' : '[name].[hash].css',
      chunkFilename: devMode ? '[id].css' : '[id].[hash].css',
    }),
    new PhpManifestPlugin(),
    new webpack.SourceMapDevToolPlugin({})
  ],
  optimization: {
    minimize: !devMode,
    splitChunks: {
      chunks: 'async',
      minSize: 30000,
      maxSize: 0,
      minChunks: 1,
      maxAsyncRequests: 5,
      maxInitialRequests: 3,
      automaticNameDelimiter: '~',
      name: true,
      cacheGroups: {
        vendors: {
          test: /[\\/]node_modules[\\/]/,
          priority: -10
        },
        default: {
          minChunks: 2,
          priority: -20,
          reuseExistingChunk: true
        }
      }
    }
  }
};
